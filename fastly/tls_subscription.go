package fastly

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/google/jsonapi"
)

// TLSSubscription represents a managed TLS certificate
type TLSSubscription struct {
	ID                   string                        `jsonapi:"primary,tls_subscription"`
	CertificateAuthority string                        `jsonapi:"attr,certificate_authority"`
	State                string                        `jsonapi:"attr,state"`
	CreatedAt            *time.Time                    `jsonapi:"attr,created_at,iso8601"`
	UpdatedAt            *time.Time                    `jsonapi:"attr,updated_at,iso8601"`
	Configuration        *TLSConfiguration             `jsonapi:"relation,tls_configuration"`
	Domains              []*TLSDomain                  `jsonapi:"relation,tls_domains"`
	Certificates         []*TLSSubscriptionCertificate `jsonapi:"relation,tls_certificates"`
	Authorizations       []*TLSAuthorizations          `jsonapi:"relation,tls_authorizations"`
}

type TLSSubscriptionCertificate struct {
	ID string `jsonapi:"primary,tls_certificate"`
}

type TLSAuthorizations struct {
	ID string `jsonapi:"primary,tls_authorization"`
	// Nested structs only work with values, not pointers. See https://github.com/google/jsonapi/pull/99
	Challenges []TLSChallenge `jsonapi:"attr,challenges"`
	CreatedAt  *time.Time     `jsonapi:"attr,created_at,iso8601,omitempty"`
	UpdatedAt  *time.Time     `jsonapi:"attr,updated_at,iso8601,omitempty"`
	State      string         `jsonapi:"attr,state,omitempty"`
}

type TLSChallenge struct {
	Type       string   `jsonapi:"attr,type"`
	RecordType string   `jsonapi:"attr,record_type"`
	RecordName string   `jsonapi:"attr,record_name"`
	Values     []string `jsonapi:"attr,values"`
}

// ListTLSSubscriptionsInput is used as input to the ListTLSSubscriptions function
type ListTLSSubscriptionsInput struct {
	// Limit the returned subscriptions by state. Valid values are pending, processing, issued, and renewing. Accepts parameters: not (e.g., filter[state][not]=renewing).
	FilterState string
	// Limit the returned subscriptions to those that include the specific domain.
	FilterTLSDomainsID string
	// Include related objects. Optional, comma-separated values. Permitted values: tls_authorizations.
	Include string
	// Current page.
	PageNumber int
	// Number of records per page.
	PageSize int
	// The order in which to list the results by creation date. Accepts created_at (ascending sort order) or -created_at (descending).
	Sort string
}

// formatFilters converts user input into query parameters for filtering
func (s *ListTLSSubscriptionsInput) formatFilters() map[string]string {
	result := map[string]string{}
	pairings := map[string]interface{}{
		"filter[state]":          s.FilterState,
		"filter[tls_domains.id]": s.FilterTLSDomainsID,
		"include":                s.Include,
		"page[number]":           s.PageNumber,
		"page[size]":             s.PageSize,
		"sort":                   s.Sort,
	}

	for key, v := range pairings {
		switch value := v.(type) {
		case string:
			if value != "" {
				result[key] = value
			}
		case int:
			if value != 0 {
				result[key] = strconv.Itoa(value)
			}
		}
	}
	return result
}

// ListTLSSubscriptions lists all managed TLS subscriptions
func (c *Client) ListTLSSubscriptions(i *ListTLSSubscriptionsInput) ([]*TLSSubscription, error) {
	response, err := c.Get("/tls/subscriptions", &RequestOptions{
		Params: i.formatFilters(),
		Headers: map[string]string{
			"Accept": "application/vnd.api+json", // Needed for "include" but seemingly not the other fields
		},
	})
	if err != nil {
		return nil, err
	}

	data, err := jsonapi.UnmarshalManyPayload(response.Body, reflect.TypeOf(new(TLSSubscription)))
	if err != nil {
		return nil, err
	}

	// Convert slice of interface{}s to a slice of TLSSubscription structs
	subscriptions := make([]*TLSSubscription, len(data))
	for i := range data {
		typed, ok := data[i].(*TLSSubscription)
		if !ok {
			return nil, fmt.Errorf("unexpected response type: %T", data[i])
		}
		subscriptions[i] = typed
	}

	return subscriptions, nil
}

type CreateTLSSubscriptionInput struct {
	// ID value is ignored and should not be set, needed to make JSONAPI work correctly.
	ID string `jsonapi:"primary,tls_subscription"`
	// CertificateAuthority is the entity that issues and certifies the TLS certificates for your subscription. Valid values are lets-encrypt or globalsign.
	CertificateAuthority string `jsonapi:"attr,certificate_authority,omitempty"`
	// Configuration options that apply to the enabled domains on this subscription. Only ID needs to be populated
	Configuration *TLSConfiguration `jsonapi:"relation,tls_configuration,omitempty"`
	// Domain list to enable TLS for. Only the ID fields of each one need to be set.
	Domain []*TLSDomain `jsonapi:"relation,tls_domain"`
}

func (c *Client) CreateTLSSubscription(i *CreateTLSSubscriptionInput) (*TLSSubscription, error) {
	if len(i.Domain) == 0 {
		return nil, ErrMissingTLSDomain
	}

	response, err := c.PostJSONAPI("/tls/subscriptions", i, nil)
	if err != nil {
		return nil, err
	}

	var subscription TLSSubscription
	err = jsonapi.UnmarshalPayload(response.Body, &subscription)
	if err != nil {
		return nil, err
	}

	return &subscription, nil
}

type GetTLSSubscriptionInput struct {
	// ID of the TLS subscription to fetch.
	ID string
	// Include related objects. Optional, comma-separated values. Permitted values: tls_authorizations.
	Include *string
}

func (c *Client) GetTLSSubscription(i *GetTLSSubscriptionInput) (*TLSSubscription, error) {
	if i.ID == "" {
		return nil, ErrMissingID
	}

	path := fmt.Sprintf("/tls/subscriptions/%s", i.ID)

	requestOptions := &RequestOptions{
		Headers: map[string]string{
			"Accept": "application/vnd.api+json", // this is required otherwise the params don't work
		},
	}

	if i.Include != nil {
		requestOptions.Params = map[string]string{"include": *i.Include}
	}

	response, err := c.Get(path, requestOptions)
	if err != nil {
		return nil, err
	}

	var subscription TLSSubscription
	err = jsonapi.UnmarshalPayload(response.Body, &subscription)
	if err != nil {
		return nil, err
	}

	return &subscription, err
}

type DeleteTLSSubscriptionInput struct {
	// ID of the TLS subscription to delete.
	ID string
}

func (c *Client) DeleteTLSSubscription(i *DeleteTLSSubscriptionInput) error {
	if i.ID == "" {
		return ErrMissingID
	}

	path := fmt.Sprintf("/tls/subscriptions/%s", i.ID)
	_, err := c.Delete(path, nil)
	return err
}
