package falco

import (
	"bufio"
	"io"
	"time"
)

func skewedDuration(d time.Duration) time.Duration {
	return time.Duration(float64(d) * 1.10)
}

func readLineByLine(r io.Reader) ([]string, error) {
	var res []string
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		res = append(res, scanner.Text())
	}
	if scanner.Err() != nil {
		return nil, scanner.Err()
	}
	return res, nil
}

func removeFromArgs(args []string, arg string, nparams int) []string {
	var res []string
	for i := 0; i < len(args); i++ {
		if args[i] == arg {
			i += nparams
		} else {
			res = append(res, args[i])
		}
	}
	return res
}
