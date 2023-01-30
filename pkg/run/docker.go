package run

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/strslice"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

type DockerRunnerOptions struct {
	Privileged bool
	Binds      []string
}

type dockerRunner struct {
	m          sync.Mutex
	image      string
	entryPoint string
	options    DockerRunnerOptions
}

// NewDockerRunner returns a runner that runs a container image with Docker
func NewDockerRunner(image, entryPoint string, options *DockerRunnerOptions) (Runner, error) {
	res := &dockerRunner{
		image:      image,
		entryPoint: entryPoint,
	}
	if options != nil {
		res.options = *options
	}

	// need to pull the image
	err := res.withClient(context.Background(), func(cli *client.Client) error {
		logrus.WithField("image", res.image).Debugf("pulling docker image")
		reader, err := cli.ImagePull(context.Background(), res.image, types.ImagePullOptions{})
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(reader)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			logrus.Debugf(scanner.Text())
		}
		defer reader.Close()
		return scanner.Err()
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
func (d *dockerRunner) WorkDir() string {
	// note: this is constant after construction and does not need
	// mutex protection
	// note: the working directory is the root dir itself, because
	// the executable will run inside a container
	// todo: figure out if root dir can cause issues
	return "/"
}

func (d *dockerRunner) withClient(ctx context.Context, do func(*client.Client) error) error {
	// create a new Docker client
	logrus.Debugf("creating new docker client")
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	// perform action
	return do(cli)
}

func (d *dockerRunner) withNewContainer(ctx context.Context, cli *client.Client, do func(containerID string) error) (err error) {
	// create a new container
	var resp container.ContainerCreateCreatedBody
	logrus.WithField("image", d.image).WithField("privileged", d.options.Privileged).Debugf("creating new docker container")
	resp, err = cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: d.image,
			// todo: the whole docker runner may be simplified by:
			//   1) copying archive before starting (and controlling the workdir)
			//   2) use a custom entrypoint and args here
			Entrypoint: strslice.StrSlice{"/bin/bash", "-c", "--", "while true; do sleep 30; done;"},
		},
		&container.HostConfig{
			Privileged: d.options.Privileged,
			Binds:      d.options.Binds,
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

// todo: check that everything is ok here
// contract:
// if a file is a relpath, or is within the work dir, it's moved in the
// workdir
// if file is an absolute path, it is accessed as-is (note: this can have issues
// for docker (let's see, maybe mounting will be enough))
func (d *dockerRunner) createFilesArchive(opts *runOpts) ([]byte, error) {
	var buf bytes.Buffer
	if err := tarFiles(&buf, opts.files...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *dockerRunner) Run(ctx context.Context, options ...RunnerOption) (retErr error) {
	d.m.Lock()
	defer d.m.Unlock()

	var filesArchive []byte
	opts := buildRunOptions(options...)
	filesArchive, retErr = d.createFilesArchive(opts)
	if retErr != nil {
		return retErr
	}

	return d.withClient(ctx, func(cli *client.Client) error {
		return d.withNewContainer(ctx, cli, func(containerID string) (err error) {
			log := logrus.WithField("containerID", containerID)
			// copy files archive into container
			log.Debugf("copying file archive")
			err = cli.CopyToContainer(ctx,
				containerID,
				d.WorkDir(),
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

			// execute entrypoint in the container
			cmd := []string{d.entryPoint}
			cmd = append(cmd, opts.args...)
			log.WithField("cmd", strings.Join(cmd, " ")).Debugf("execute entrypoint in container")
			execResp, err := cli.ContainerExecCreate(ctx, containerID, types.ExecConfig{
				Privileged:   d.options.Privileged,
				AttachStdin:  false,
				AttachStderr: true,
				AttachStdout: true,
				Cmd:          cmd,
			})
			if err != nil {
				return err
			}

			// attach to the running command execution and copy stdout
			// and stderr in async
			log.Debugf("attaching to command execution")
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

func tarFiles(w io.Writer, files ...FileAccessor) (err error) {
	tw := tar.NewWriter(w)
	defer func() {
		err = multierr.Append(err, tw.Close())
	}()

	for _, file := range files {
		fileContent, err := file.Content()
		if err != nil {
			return err
		}

		// create a new file header
		header := &tar.Header{
			Name:     file.Name(),
			ModTime:  time.Now(),
			Mode:     int64(0777),
			Typeflag: tar.TypeReg,
			Size:     int64(len(fileContent)),
		}

		// write the header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// copy file data into tar writer
		if _, err := io.Copy(tw, bytes.NewReader(fileContent)); err != nil {
			return err
		}
	}

	return nil
}
