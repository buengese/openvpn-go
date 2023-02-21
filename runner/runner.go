package runner

type Runner interface {
	// Run runs command with given arguments and returns stdout, stderr and error
	Run(arguments []string) (stdout string, stderr string, err error)
}
