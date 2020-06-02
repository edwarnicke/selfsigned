selfsigned provides a simple means to create a selfsigned Spiffe [x509svid.Source](https://github.com/spiffe/go-spiffe/blob/master/v2/svid/x509svid/source.go#L4) + 
[x509bundle.Source](https://github.com/spiffe/go-spiffe/blob/master/v2/bundle/x509bundle/source.go#L8)

When working with spiffe, it is sometimes desirable to be able to function without  spiffe workloadapi provider, particularly
for purposes of local test.

selfsigned seeks to mirror the behavior of [workloadapi.NewX509Source](https://github.com/spiffe/go-spiffe/blob/master/v2/workloadapi/x509source.go#L31), it can be used even in production
code by using

selfsigned.IfSpiffeUnvailable().NewX509Source() as a drop in replacement for workloadapi.NewX509Source().

selfsigned.IfSpiffeUnvailable().NewX509Source() will return a selfsigned Source if Spiffe is unavailable, and
the result of worloadapi.NewX509Source() if Spiffe is available.
