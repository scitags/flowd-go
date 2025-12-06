package api

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/scitags/flowd-go/types"
)

var dummyFlowID = types.FlowID{
	// State:    glowd.START,
	Family:      types.IPv6,
	Protocol:    types.TCP,
	Src:         netip.AddrPortFrom(netip.MustParseAddr("::1"), 2345),
	Dst:         netip.AddrPortFrom(netip.MustParseAddr("::1"), 5777),
	Activity:    0xFFFF,
	Experiment:  0xFFFF,
	Application: types.SYSLOG_APP_NAME,
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
	tmp.State = types.START
	tmp.StartTs = time.Now()

	cc.flowChannel <- tmp
	return c.JSONPretty(http.StatusOK, &tmp, JSON_PRETTY_INDENT)
}

func handleDummyEndFlow(c echo.Context) error {
	cc := c.(*extendedContext)

	tmp := dummyFlowID
	tmp.State = types.END
	tmp.EndTs = time.Now()

	cc.flowChannel <- tmp
	return c.JSONPretty(http.StatusOK, &tmp, JSON_PRETTY_INDENT)
}

func handleFlow(c echo.Context) error {
	cc := c.(*extendedContext)

	flowID := types.FlowID{}
	if err := cc.Bind(&flowID); err != nil {
		return c.JSONPretty(http.StatusBadRequest, err, JSON_PRETTY_INDENT)
	}

	cc.flowChannel <- flowID

	return c.JSONPretty(http.StatusOK, &flowID, JSON_PRETTY_INDENT)
}
