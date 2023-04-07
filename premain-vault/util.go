package main

import (
	"fmt"
	"os"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func envConfig(name string) string {
	value, ok := os.LookupEnv(name)

	if !ok {
		panic(fmt.Errorf("environment variable '%s' missing", name))
	}

	return value
}
