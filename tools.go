//go:build tools

package main

/*
 * This file allows us to add the dependency on go-md2man so that we can leverage
 * it from a `go:generate` statement without polluting the production binary. Note
 * this file will never be compiled as the `tools` build tag will never be provided.
 * See https://www.jvt.me/posts/2022/06/15/go-tools-dependency-management/ for more
 * information on this pattern. Bear in mind Go 1.24 introduces `go tool`, which
 * makes all this much easier!
 */

import (
	_ "github.com/cpuguy83/go-md2man/v2"
)
