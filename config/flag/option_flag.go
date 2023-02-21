package flag

func OptionFlag(name string) optionFlag {
	return optionFlag{name: name}
}

type optionFlag struct {
	name string
}

func (o optionFlag) GetName() string {
	return o.name
}

func (o optionFlag) ToCli() ([]string, error) {
	return []string{"--" + o.name}, nil
}

func (o optionFlag) ToConfig() (string, error) {
	return o.name, nil
}

func FromConfig(content string) optionFlag {
	return optionFlag{name: content}
}

func (o optionFlag) String() string {
	return o.name
}
