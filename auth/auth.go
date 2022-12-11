package auth

import (
	"context"
	"reflect"

	"golang.org/x/xerrors"
)

type Permission string

func WithPerm(ctx context.Context, token string, perms []Permission) context.Context {
	return context.WithValue(ctx, token, perms)
}

func HasPerm(ctx context.Context, token string, defaultPerms []Permission, perm Permission) bool {
	callerPerms, ok := ctx.Value(token).([]Permission)
	if !ok {
		callerPerms = defaultPerms
	}

	for _, callerPerm := range callerPerms {
		if callerPerm == perm {
			return true
		}
	}
	return false
}

func PermissionedProxy(token string, validPerms, defaultPerms []Permission, in interface{}, out interface{}) {
	rint := reflect.ValueOf(out).Elem()
	ra := reflect.ValueOf(in)

	for f := 0; f < rint.NumField(); f++ {
		field := rint.Type().Field(f)
		requiredPerm := Permission(field.Tag.Get("perm"))
		if requiredPerm == "" {
			panic("missing 'perm' tag on " + field.Name) // ok
		}

		// Validate perm tag
		ok := false
		for _, perm := range validPerms {
			if requiredPerm == perm {
				ok = true
				break
			}
		}
		if !ok {
			panic("unknown 'perm' tag on " + field.Name) // ok
		}

		fn := ra.MethodByName(field.Name)

		rint.Field(f).Set(reflect.MakeFunc(field.Type, func(args []reflect.Value) (results []reflect.Value) {
			ctx := args[0].Interface().(context.Context)
			if HasPerm(ctx, token, defaultPerms, requiredPerm) {
				return fn.Call(args)
			}

			err := xerrors.Errorf("missing permission to invoke '%s' (need '%s')", field.Name, requiredPerm)
			rerr := reflect.ValueOf(&err).Elem()

			if field.Type.NumOut() == 2 {
				return []reflect.Value{
					reflect.Zero(field.Type.Out(0)),
					rerr,
				}
			} else {
				return []reflect.Value{rerr}
			}
		}))
	}
}
