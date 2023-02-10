package run

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"io"
	"path"
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
	entrypoint string
	options    DockerRunnerOptions
}

// NewDockerRunner returns a runner that runs a container image with Docker
func NewDockerRunner(image, entrypoint string, options *DockerRunnerOptions) (Runner, error) {
	res := &dockerRunner{image: image, entrypoint: entrypoint}
	if options != nil {
		res.options = *options
	}

	// attempt pulling the image
	err := res.withClient(context.Background(), func(cli *client.Client) error {
		logrus.WithField("image", res.image).Debugf("pulling docker image")
		reader, err := cli.ImagePull(context.Background(), res.image, types.ImagePullOptions{})
		if err != nil {
			return err
		}

		// consume output and wait up until pulling is finished
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
	// todo(jasondellaluce): figure out if root dir can cause issues
	return "/"
}

func (d *dockerRunner) Run(ctx context.Context, options ...RunnerOption) (retErr error) {
	d.m.Lock()
	defer d.m.Unlock()
	opts := buildRunOptions(options...)
	return d.withClient(ctx, func(cli *client.Client) (err error) {
		// create a container
		var containerID string
		containerID, err = d.createContainer(ctx, cli, opts.args)
		if err != nil {
			return err
		}
		defer func() { err = multierr.Append(err, d.removeContainer(cli, containerID)) }()

		// copy all loaded files into the container
		err = d.copyFilesArchive(ctx, cli, containerID, opts.files)
		if err != nil {
			return err
		}

		// attach to container
		logrus.WithField("containerID", containerID).Debugf("attaching to docker container")
		hr, err := cli.ContainerAttach(ctx, containerID, types.ContainerAttachOptions{
			Stdout: true,
			Stderr: true,
			Stream: true,
		})
		if err != nil {
			return err
		}
		defer hr.Close()

		// start the container
		err = d.startContainer(ctx, cli, containerID)
		if err != nil {
			return err
		}
		defer func() { err = multierr.Append(err, d.stopContainer(cli, containerID)) }()

		// pipe and collect all container outputs
		_, err = stdcopy.StdCopy(opts.stdout, opts.stderr, hr.Reader)
		return err
	})
}

func (d *dockerRunner) withClient(ctx context.Context, do func(*client.Client) error) error {
	logrus.Debugf("creating new docker client")
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()
	return do(cli)
}

func (d *dockerRunner) createContainer(ctx context.Context, cli *client.Client, args []string) (id string, err error) {
	var resp container.ContainerCreateCreatedBody
	logrus.WithField("image", d.image).WithField("privileged", d.options.Privileged).Debugf("creating new docker container")
	resp, err = cli.ContainerCreate(
		ctx,
		&container.Config{
			Image:      d.image,
			Entrypoint: strslice.StrSlice(append([]string{d.entrypoint}, args...)),
		},
		&container.HostConfig{
			Privileged: d.options.Privileged,
			Binds:      d.options.Binds,
		},
		nil, nil, "")
	if err != nil {
		return "", err
	}
	return resp.ID, err
}

func (d *dockerRunner) removeContainer(cli *client.Client, containerID string) error {
	// note: the context's deadline may be done, but we still want to wait
	ctx := context.Background()
	logrus.WithField("containerID", containerID).Debugf("removing docker container")
	return cli.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{Force: true})
}

func (d *dockerRunner) startContainer(ctx context.Context, cli *client.Client, containerID string) error {
	logrus.WithField("containerID", containerID).Debugf("starting docker container")
	return cli.ContainerStart(ctx, containerID, types.ContainerStartOptions{})
}

func (d *dockerRunner) stopContainer(cli *client.Client, containerID string) error {
	// note: the context's deadline may be done, but we still want to wait
	ctx := context.Background()
	logrus.WithField("containerID", containerID).Debugf("stopping docker container")
	return cli.ContainerStop(ctx, containerID, nil)
}

func (d *dockerRunner) copyFilesArchive(ctx context.Context, cli *client.Client, containerID string, files []FileAccessor) error {
	logrus.WithField("containerID", containerID).Debugf("creating files archive")
	var buf bytes.Buffer
	if err := d.tarFiles(d.WorkDir(), &buf, files...); err != nil {
		return err
	}

	logrus.WithField("containerID", containerID).Debugf("copying files archive")
	return cli.CopyToContainer(ctx,
		containerID,
		d.WorkDir(),
		bytes.NewReader(buf.Bytes()),
		types.CopyToContainerOptions{AllowOverwriteDirWithFile: true},
	)
}

func (d *dockerRunner) tarFiles(baseDir string, w io.Writer, files ...FileAccessor) (err error) {
	tw := tar.NewWriter(w)
	defer func() {
		err = multierr.Append(err, tw.Close())
	}()

	for _, file := range files {
		fileContent, err := file.Content()
		if err != nil {
			return err
		}

		// if file's name is a relative path, copy it in the workdir.
		// if file's name is an absolute path, it is copied as-is
		fileName := file.Name()
		if !path.IsAbs(fileName) {
			fileName = baseDir + "/" + fileName
		}

		// create a new file header
		header := &tar.Header{
			Name:     fileName,
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
