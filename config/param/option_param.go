package param

import (
	"errors"
	"strings"
)

var (
	ErrNoParam = errors.New("no param")
)

func OptionParam(name string, values ...string) optionParam {
	return optionParam{name: name, values: values}
}

type optionParam struct {
	name   string
	values []string
}

func (o optionParam) GetName() string {
	return o.name
}

func (o optionParam) ToCli() ([]string, error) {
	return append([]string{"--" + o.name}, o.values...), nil
}

func (o optionParam) ToConfig() (string, error) {
	return o.name + " " + strings.Join(o.values, " "), nil
}

func (o optionParam) String() string {
	return o.name + " " + strings.Join(o.values, " ")
}

func FromConfig(content string) (optionParam, error) {
	parts := strings.Split(content, " ")
	if len(parts) < 2 {
		return optionParam{}, ErrNoParam
	}
	return optionParam{name: parts[0], values: parts[1:]}, nil
}
