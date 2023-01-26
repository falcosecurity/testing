package falco

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/falcosecurity/falco/regression-tests/pkg/utils"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

type dockerRunner struct {
	image      string
	privileged bool
}

// NewDockerRunner returns a Falco runner that runs a container image with Docker
func NewDockerRunner(image string, privileged bool) Runner {
	return &dockerRunner{
		image:      image,
		privileged: privileged,
	}
}

func (d *dockerRunner) withClientAndImage(ctx context.Context, do func(*client.Client) error) error {
	// create a new Docker client
	logrus.Debugf("creating new docker client")
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	// todo: pulling the image takes time and there is no clear way to wait
	// up until it's finished. For now, let's assume that the used image is
	// already present in the local daemon
	// // pull new Image
	// logrus.WithField("image", d.image).Debugf("pulling docker image")
	// reader, err := cli.ImagePull(context.Background(), d.image, types.ImagePullOptions{
	// 	All: true,
	// })
	// if err != nil {
	// 	return err
	// }
	// defer reader.Close()

	// perform action
	return do(cli)
}

func (d *dockerRunner) withNewContainer(ctx context.Context, cli *client.Client, do func(containerID string) error) (err error) {
	// create a new container
	var resp container.ContainerCreateCreatedBody
	var binds []string
	if d.privileged {
		binds = []string{
			"/var/run/docker.sock:/host/var/run/docker.sock",
			"/proc:/host/proc:ro",
			"/dev:/host/dev",
		}
	}
	logrus.WithField("image", d.image).WithField("privileged", d.privileged).Debugf("creating new docker container")
	resp, err = cli.ContainerCreate(
		ctx,
		&container.Config{Image: d.image},
		&container.HostConfig{
			Privileged: d.privileged,
			Binds:      binds,
		},
		nil, nil, "")
	if err != nil {
		return err
	}

	// force removing the container once finished
	defer func() {
		logrus.WithField("containerID", resp.ID).Debugf("removing docker container")
		err = multierr.Append(
			err,
			cli.ContainerRemove(
				context.Background(),
				resp.ID,
				types.ContainerRemoveOptions{Force: true},
			),
		)
	}()

	// start the container
	logrus.WithField("containerID", resp.ID).Debugf("starting docker container")
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return err
	}

	// perform action
	return do(resp.ID)
}

func (d *dockerRunner) createFilesArchive(opts *runOpts) ([]byte, error) {
	var buf bytes.Buffer
	if err := utils.TarFiles(&buf, opts.files...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *dockerRunner) Run(ctx context.Context, options ...RunnerOption) (retErr error) {
	var filesArchive []byte
	opts := buildRunOptions(options...)
	filesArchive, retErr = d.createFilesArchive(opts)
	if retErr != nil {
		return retErr
	}

	return d.withClientAndImage(ctx, func(cli *client.Client) error {
		return d.withNewContainer(ctx, cli, func(containerID string) (err error) {
			log := logrus.WithField("containerID", containerID)
			// copy files archive into container
			archiveDir := "/" // todo: figure out if root dir can cause issues
			log.Debugf("copying file archive")
			err = cli.CopyToContainer(ctx,
				containerID,
				archiveDir,
				bytes.NewReader(filesArchive),
				types.CopyToContainerOptions{AllowOverwriteDirWithFile: true},
			)
			if err != nil {
				return err
			}

			// start a wait group and wait for all routines to finish before
			// returning. Once all are done, all errors collected asynchronously
			// are appended.
			var wg sync.WaitGroup
			var eventErr error
			var ioCopyErr error
			defer func() {
				err = multierr.Append(err, eventErr)
				err = multierr.Append(err, ioCopyErr)
			}()
			defer wg.Wait()
			defer log.Debugf("waiting for all docker async routines")

			// start listening to docker events to understand when the
			// command execution will terminate.
			diedC := make(chan bool) // closed when command execution dies
			quitC := make(chan bool) // closed when needing to quit
			defer close(quitC)
			wg.Add(1)
			log.Debugf("start listening for docker events")
			go func() {
				eventC, eventErrC := cli.Events(ctx, types.EventsOptions{})
				defer wg.Done()
				defer close(diedC)
				for {
					select {
					case <-quitC:
						return
					case e := <-eventErrC:
						eventErr = multierr.Append(eventErr, e)
						return
					case ev := <-eventC:
						if ev.ID == containerID && ev.Type == "container" && ev.Action == "exec_die" {
							exitCode := 0
							if ecStr, ok := ev.Actor.Attributes["exitCode"]; ok {
								exitCode, eventErr = strconv.Atoi(ecStr)
								if eventErr == nil && exitCode != 0 {
									eventErr = &ExitCodeError{Code: exitCode}
								}
							}
							return
						}
					}
				}
			}()

			// execute falco in the container
			cmd := []string{DefaultFalcoExecutable}
			cmd = append(cmd, opts.args...)
			log.WithField("cmd", strings.Join(cmd, " ")).Debugf("execute falco command in container")
			execResp, err := cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
				Privileged:   d.privileged,
				AttachStdin:  false,
				AttachStderr: true,
				AttachStdout: true,
				Cmd:          cmd,
			})
			if err != nil {
				return err
			}

			// attach to the running Falco execution and copy stdout
			// and stderr in async
			log.Debugf("attaching to falco command execution")
			hr, err := cli.ContainerExecAttach(context.Background(), execResp.ID, types.ExecStartCheck{})
			if err != nil {
				return err
			}
			defer hr.Close()
			wg.Add(1)
			log.Debugf("start piping container's stderr and stdout")
			go func() {
				defer wg.Done()
				_, ioCopyErr = stdcopy.StdCopy(opts.stdout, opts.stderr, hr.Reader)
			}()

			// wait for container termination
			log.Debugf("waiting for container's termiantion")
			statusC, errC := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
			select {
			case <-diedC:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			case err := <-errC:
				return err
			case c := <-statusC:
				if c.Error != nil {
					return fmt.Errorf(c.Error.Message)
				}
				return nil
			}
		})
	})
}
