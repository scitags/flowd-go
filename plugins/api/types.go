package api

import (
	"github.com/labstack/echo/v4"
	glowd "github.com/scitags/flowd-go"
)

const (
	JSON_PRETTY_INDENT string = "    "
)

type rootResponse struct {
	ApiRoutes []*echo.Route
}

type extendedContext struct {
	echo.Context
	apiRoutes   []*echo.Route
	flowChannel chan<- glowd.FlowID
}
