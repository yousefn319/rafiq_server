package main

import (
	"errors"
	"reflect"
	"strings"

	crand "crypto/rand"

	"github.com/jackc/pgx/v5/pgconn"
)

func StructToValueMap(s interface{}) map[string]any {
	res := make(map[string]any)
	v := reflect.ValueOf(s)
	t := reflect.TypeOf(s)
	for i := 0; i < t.NumField(); i++ {
		fv := v.Field(i).Interface()
		tag := t.Field(i).Tag.Get("db")
		if tag == "-" {
			continue
		} else if tag != "" {
			res[tag] = fv
		} else {
			res[strings.ToLower(t.Field(i).Name)] = fv
		}
	}
	return res
}

func ToPgError(err error) *pgconn.PgError {
	var pgErr *pgconn.PgError
	errors.As(err, &pgErr)
	return pgErr
}

func MakeSecret() ([]byte, error) {
	secret := make([]byte, 32)
	_, err := crand.Read(secret)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
