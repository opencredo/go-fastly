package fastly

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/google/jsonapi"
)

type CustomTLSDomain struct {
	ID               string                         `jsonapi:"primary,tls_domain"`
	TLSActivations   []*TLSActivationRelationship   `jsonapi:"relation,tls_activations,omitempty"`
	TLSCertificates  []*TLSCertificateRelationship  `jsonapi:"relation,tls_certificates,omitempty"`
	TLSSubscriptions []*TLSSubscriptionRelationship `jsonapi:"relation,tls_subscriptions,omitempty"`
}

type TLSActivationRelationship struct {
	ID string `jsonapi:"primary,tls_activation"`
}

type TLSCertificateRelationship struct {
	ID string `jsonapi:"primary,tls_certificate"`
}

type TLSSubscriptionRelationship struct {
	ID string `jsonapi:"primary,tls_subscription"`
}

type ListTLSDomainsInput struct {
	FilterInUse             *bool
	FilterTLSCertificateID  string
	FilterTLSSubscriptionID string
	Include                 string
	PageNumber              int
	PageSize                int
	Sort                    string
}

func (l *ListTLSDomainsInput) formatFilters() map[string]string {
	result := map[string]string{}
	pairings := map[string]interface{}{
		"filter[in_use]":               l.FilterInUse,
		"filter[tls_certificate.id]":   l.FilterTLSCertificateID,
		"filter[tls_subscriptions.id]": l.FilterTLSSubscriptionID,
		"include":                      l.Include,
		"page[number]":                 l.PageNumber,
		"page[size]":                   l.PageSize,
		"sort":                         l.Sort,
	}

	for key, value := range pairings {
		switch t := value.(type) {
		case string:
			if t != "" {
				result[key] = t
			}
		case int:
			if t != 0 {
				result[key] = strconv.Itoa(t)
			}
		case *bool:
			if t != nil {
				result[key] = strconv.FormatBool(*t)
			}
		}
	}

	return result
}

func (c *Client) ListTLSDomains(i *ListTLSDomainsInput) ([]*CustomTLSDomain, error) {
	p := "/tls/domains"
	filters := &RequestOptions{
		Params: i.formatFilters(),
		Headers: map[string]string{
			"Accept": "application/vnd.api+json", // this is required otherwise the filters don't work
		},
	}

	r, err := c.Get(p, filters)
	if err != nil {
		return nil, err
	}

	data, err := jsonapi.UnmarshalManyPayload(r.Body, reflect.TypeOf(new(CustomTLSDomain)))
	if err != nil {
		return nil, err
	}

	a := make([]*CustomTLSDomain, len(data))
	for i := range data {
		typed, ok := data[i].(*CustomTLSDomain)
		if !ok {
			return nil, fmt.Errorf("unexpected response type: %T", data[i])
		}
		a[i] = typed
	}

	return a, nil
}
