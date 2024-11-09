package api

import (
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	glowd "github.com/scitags/flowd-go"
)

var dummyFlowID = glowd.FlowID{
	// State:    glowd.START,
	Protocol: glowd.TCP,
	Src: glowd.IPPort{
		IP:   net.ParseIP("::1"),
		Port: 2345,
	},
	Dst: glowd.IPPort{
		IP:   net.ParseIP("::1"),
		Port: 5777,
	},
	Activity:   0xFFFF,
	Experiment: 0xFFFF,
	// StartTs:    time.Now(),
}

func handleRoot(c echo.Context) error {
	cc := c.(*extendedContext)
	return c.JSONPretty(http.StatusOK, &rootResponse{
		ApiRoutes: cc.apiRoutes,
	}, JSON_PRETTY_INDENT)
}

func handleDummyStartFlow(c echo.Context) error {
	cc := c.(*extendedContext)

	tmp := dummyFlowID
	tmp.State = glowd.START
	tmp.StartTs = time.Now()

	cc.flowChannel <- tmp
	return c.JSONPretty(http.StatusOK, &tmp, JSON_PRETTY_INDENT)
}

func handleDummyEndFlow(c echo.Context) error {
	cc := c.(*extendedContext)

	tmp := dummyFlowID
	tmp.State = glowd.END
	tmp.EndTs = time.Now()

	cc.flowChannel <- tmp
	return c.JSONPretty(http.StatusOK, &tmp, JSON_PRETTY_INDENT)
}
