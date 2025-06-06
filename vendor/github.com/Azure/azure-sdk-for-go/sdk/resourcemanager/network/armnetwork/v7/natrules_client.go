// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator. DO NOT EDIT.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armnetwork

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// NatRulesClient contains the methods for the NatRules group.
// Don't use this type directly, use NewNatRulesClient() instead.
type NatRulesClient struct {
	internal       *arm.Client
	subscriptionID string
}

// NewNatRulesClient creates a new instance of NatRulesClient with the specified values.
//   - subscriptionID - The subscription credentials which uniquely identify the Microsoft Azure subscription. The subscription
//     ID forms part of the URI for every service call.
//   - credential - used to authorize requests. Usually a credential from azidentity.
//   - options - pass nil to accept the default values.
func NewNatRulesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) (*NatRulesClient, error) {
	cl, err := arm.NewClient(moduleName, moduleVersion, credential, options)
	if err != nil {
		return nil, err
	}
	client := &NatRulesClient{
		subscriptionID: subscriptionID,
		internal:       cl,
	}
	return client, nil
}

// BeginCreateOrUpdate - Creates a nat rule to a scalable vpn gateway if it doesn't exist else updates the existing nat rules.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The resource group name of the VpnGateway.
//   - gatewayName - The name of the gateway.
//   - natRuleName - The name of the nat rule.
//   - natRuleParameters - Parameters supplied to create or Update a Nat Rule.
//   - options - NatRulesClientBeginCreateOrUpdateOptions contains the optional parameters for the NatRulesClient.BeginCreateOrUpdate
//     method.
func (client *NatRulesClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, natRuleParameters VPNGatewayNatRule, options *NatRulesClientBeginCreateOrUpdateOptions) (*runtime.Poller[NatRulesClientCreateOrUpdateResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.createOrUpdate(ctx, resourceGroupName, gatewayName, natRuleName, natRuleParameters, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[NatRulesClientCreateOrUpdateResponse]{
			FinalStateVia: runtime.FinalStateViaAzureAsyncOp,
			Tracer:        client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[NatRulesClientCreateOrUpdateResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// CreateOrUpdate - Creates a nat rule to a scalable vpn gateway if it doesn't exist else updates the existing nat rules.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
func (client *NatRulesClient) createOrUpdate(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, natRuleParameters VPNGatewayNatRule, options *NatRulesClientBeginCreateOrUpdateOptions) (*http.Response, error) {
	var err error
	const operationName = "NatRulesClient.BeginCreateOrUpdate"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, gatewayName, natRuleName, natRuleParameters, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusCreated) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *NatRulesClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, natRuleParameters VPNGatewayNatRule, _ *NatRulesClientBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/vpnGateways/{gatewayName}/natRules/{natRuleName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if gatewayName == "" {
		return nil, errors.New("parameter gatewayName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{gatewayName}", url.PathEscape(gatewayName))
	if natRuleName == "" {
		return nil, errors.New("parameter natRuleName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{natRuleName}", url.PathEscape(natRuleName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	if err := runtime.MarshalAsJSON(req, natRuleParameters); err != nil {
		return nil, err
	}
	return req, nil
}

// BeginDelete - Deletes a nat rule.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The resource group name of the VpnGateway.
//   - gatewayName - The name of the gateway.
//   - natRuleName - The name of the nat rule.
//   - options - NatRulesClientBeginDeleteOptions contains the optional parameters for the NatRulesClient.BeginDelete method.
func (client *NatRulesClient) BeginDelete(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, options *NatRulesClientBeginDeleteOptions) (*runtime.Poller[NatRulesClientDeleteResponse], error) {
	if options == nil || options.ResumeToken == "" {
		resp, err := client.deleteOperation(ctx, resourceGroupName, gatewayName, natRuleName, options)
		if err != nil {
			return nil, err
		}
		poller, err := runtime.NewPoller(resp, client.internal.Pipeline(), &runtime.NewPollerOptions[NatRulesClientDeleteResponse]{
			FinalStateVia: runtime.FinalStateViaLocation,
			Tracer:        client.internal.Tracer(),
		})
		return poller, err
	} else {
		return runtime.NewPollerFromResumeToken(options.ResumeToken, client.internal.Pipeline(), &runtime.NewPollerFromResumeTokenOptions[NatRulesClientDeleteResponse]{
			Tracer: client.internal.Tracer(),
		})
	}
}

// Delete - Deletes a nat rule.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
func (client *NatRulesClient) deleteOperation(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, options *NatRulesClientBeginDeleteOptions) (*http.Response, error) {
	var err error
	const operationName = "NatRulesClient.BeginDelete"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, gatewayName, natRuleName, options)
	if err != nil {
		return nil, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK, http.StatusAccepted, http.StatusNoContent) {
		err = runtime.NewResponseError(httpResp)
		return nil, err
	}
	return httpResp, nil
}

// deleteCreateRequest creates the Delete request.
func (client *NatRulesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, _ *NatRulesClientBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/vpnGateways/{gatewayName}/natRules/{natRuleName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if gatewayName == "" {
		return nil, errors.New("parameter gatewayName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{gatewayName}", url.PathEscape(gatewayName))
	if natRuleName == "" {
		return nil, errors.New("parameter natRuleName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{natRuleName}", url.PathEscape(natRuleName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// Get - Retrieves the details of a nat ruleGet.
// If the operation fails it returns an *azcore.ResponseError type.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The resource group name of the VpnGateway.
//   - gatewayName - The name of the gateway.
//   - natRuleName - The name of the nat rule.
//   - options - NatRulesClientGetOptions contains the optional parameters for the NatRulesClient.Get method.
func (client *NatRulesClient) Get(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, options *NatRulesClientGetOptions) (NatRulesClientGetResponse, error) {
	var err error
	const operationName = "NatRulesClient.Get"
	ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, operationName)
	ctx, endSpan := runtime.StartSpan(ctx, operationName, client.internal.Tracer(), nil)
	defer func() { endSpan(err) }()
	req, err := client.getCreateRequest(ctx, resourceGroupName, gatewayName, natRuleName, options)
	if err != nil {
		return NatRulesClientGetResponse{}, err
	}
	httpResp, err := client.internal.Pipeline().Do(req)
	if err != nil {
		return NatRulesClientGetResponse{}, err
	}
	if !runtime.HasStatusCode(httpResp, http.StatusOK) {
		err = runtime.NewResponseError(httpResp)
		return NatRulesClientGetResponse{}, err
	}
	resp, err := client.getHandleResponse(httpResp)
	return resp, err
}

// getCreateRequest creates the Get request.
func (client *NatRulesClient) getCreateRequest(ctx context.Context, resourceGroupName string, gatewayName string, natRuleName string, _ *NatRulesClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/vpnGateways/{gatewayName}/natRules/{natRuleName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if gatewayName == "" {
		return nil, errors.New("parameter gatewayName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{gatewayName}", url.PathEscape(gatewayName))
	if natRuleName == "" {
		return nil, errors.New("parameter natRuleName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{natRuleName}", url.PathEscape(natRuleName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *NatRulesClient) getHandleResponse(resp *http.Response) (NatRulesClientGetResponse, error) {
	result := NatRulesClientGetResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.VPNGatewayNatRule); err != nil {
		return NatRulesClientGetResponse{}, err
	}
	return result, nil
}

// NewListByVPNGatewayPager - Retrieves all nat rules for a particular virtual wan vpn gateway.
//
// Generated from API version 2024-07-01
//   - resourceGroupName - The resource group name of the VpnGateway.
//   - gatewayName - The name of the gateway.
//   - options - NatRulesClientListByVPNGatewayOptions contains the optional parameters for the NatRulesClient.NewListByVPNGatewayPager
//     method.
func (client *NatRulesClient) NewListByVPNGatewayPager(resourceGroupName string, gatewayName string, options *NatRulesClientListByVPNGatewayOptions) *runtime.Pager[NatRulesClientListByVPNGatewayResponse] {
	return runtime.NewPager(runtime.PagingHandler[NatRulesClientListByVPNGatewayResponse]{
		More: func(page NatRulesClientListByVPNGatewayResponse) bool {
			return page.NextLink != nil && len(*page.NextLink) > 0
		},
		Fetcher: func(ctx context.Context, page *NatRulesClientListByVPNGatewayResponse) (NatRulesClientListByVPNGatewayResponse, error) {
			ctx = context.WithValue(ctx, runtime.CtxAPINameKey{}, "NatRulesClient.NewListByVPNGatewayPager")
			nextLink := ""
			if page != nil {
				nextLink = *page.NextLink
			}
			resp, err := runtime.FetcherForNextLink(ctx, client.internal.Pipeline(), nextLink, func(ctx context.Context) (*policy.Request, error) {
				return client.listByVPNGatewayCreateRequest(ctx, resourceGroupName, gatewayName, options)
			}, nil)
			if err != nil {
				return NatRulesClientListByVPNGatewayResponse{}, err
			}
			return client.listByVPNGatewayHandleResponse(resp)
		},
		Tracer: client.internal.Tracer(),
	})
}

// listByVPNGatewayCreateRequest creates the ListByVPNGateway request.
func (client *NatRulesClient) listByVPNGatewayCreateRequest(ctx context.Context, resourceGroupName string, gatewayName string, _ *NatRulesClientListByVPNGatewayOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/vpnGateways/{gatewayName}/natRules"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if gatewayName == "" {
		return nil, errors.New("parameter gatewayName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{gatewayName}", url.PathEscape(gatewayName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2024-07-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header["Accept"] = []string{"application/json"}
	return req, nil
}

// listByVPNGatewayHandleResponse handles the ListByVPNGateway response.
func (client *NatRulesClient) listByVPNGatewayHandleResponse(resp *http.Response) (NatRulesClientListByVPNGatewayResponse, error) {
	result := NatRulesClientListByVPNGatewayResponse{}
	if err := runtime.UnmarshalAsJSON(resp, &result.ListVPNGatewayNatRulesResult); err != nil {
		return NatRulesClientListByVPNGatewayResponse{}, err
	}
	return result, nil
}
