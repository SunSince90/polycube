# \FirewallApi

All URIs are relative to *http://localhost:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**CreateFirewallByID**](FirewallApi.md#CreateFirewallByID) | **Post** /firewall/{name}/ | Create firewall by ID
[**CreateFirewallChainAppendByID**](FirewallApi.md#CreateFirewallChainAppendByID) | **Post** /firewall/{name}/chain/{chain_name}/append/ | Create append by ID
[**CreateFirewallChainApplyRulesByID**](FirewallApi.md#CreateFirewallChainApplyRulesByID) | **Post** /firewall/{name}/chain/{chain_name}/apply-rules/ | Create apply-rules by ID
[**CreateFirewallChainByID**](FirewallApi.md#CreateFirewallChainByID) | **Post** /firewall/{name}/chain/{chain_name}/ | Create chain by ID
[**CreateFirewallChainDeleteByID**](FirewallApi.md#CreateFirewallChainDeleteByID) | **Post** /firewall/{name}/chain/{chain_name}/delete/ | Create delete by ID
[**CreateFirewallChainInsertByID**](FirewallApi.md#CreateFirewallChainInsertByID) | **Post** /firewall/{name}/chain/{chain_name}/insert/ | Create insert by ID
[**CreateFirewallChainListByID**](FirewallApi.md#CreateFirewallChainListByID) | **Post** /firewall/{name}/chain/ | Create chain by ID
[**CreateFirewallChainResetCountersByID**](FirewallApi.md#CreateFirewallChainResetCountersByID) | **Post** /firewall/{name}/chain/{chain_name}/reset-counters/ | Create reset-counters by ID
[**CreateFirewallChainRuleByID**](FirewallApi.md#CreateFirewallChainRuleByID) | **Post** /firewall/{name}/chain/{chain_name}/rule/{id}/ | Create rule by ID
[**CreateFirewallChainRuleListByID**](FirewallApi.md#CreateFirewallChainRuleListByID) | **Post** /firewall/{name}/chain/{chain_name}/rule/ | Create rule by ID
[**DeleteFirewallByID**](FirewallApi.md#DeleteFirewallByID) | **Delete** /firewall/{name}/ | Delete firewall by ID
[**DeleteFirewallChainByID**](FirewallApi.md#DeleteFirewallChainByID) | **Delete** /firewall/{name}/chain/{chain_name}/ | Delete chain by ID
[**DeleteFirewallChainListByID**](FirewallApi.md#DeleteFirewallChainListByID) | **Delete** /firewall/{name}/chain/ | Delete chain by ID
[**DeleteFirewallChainRuleByID**](FirewallApi.md#DeleteFirewallChainRuleByID) | **Delete** /firewall/{name}/chain/{chain_name}/rule/{id}/ | Delete rule by ID
[**DeleteFirewallChainRuleListByID**](FirewallApi.md#DeleteFirewallChainRuleListByID) | **Delete** /firewall/{name}/chain/{chain_name}/rule/ | Delete rule by ID
[**ReadFirewallAcceptEstablishedByID**](FirewallApi.md#ReadFirewallAcceptEstablishedByID) | **Get** /firewall/{name}/accept-established/ | Read accept-established by ID
[**ReadFirewallByID**](FirewallApi.md#ReadFirewallByID) | **Get** /firewall/{name}/ | Read firewall by ID
[**ReadFirewallChainByID**](FirewallApi.md#ReadFirewallChainByID) | **Get** /firewall/{name}/chain/{chain_name}/ | Read chain by ID
[**ReadFirewallChainDefaultByID**](FirewallApi.md#ReadFirewallChainDefaultByID) | **Get** /firewall/{name}/chain/{chain_name}/default/ | Read default by ID
[**ReadFirewallChainListByID**](FirewallApi.md#ReadFirewallChainListByID) | **Get** /firewall/{name}/chain/ | Read chain by ID
[**ReadFirewallChainRuleActionByID**](FirewallApi.md#ReadFirewallChainRuleActionByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/action/ | Read action by ID
[**ReadFirewallChainRuleByID**](FirewallApi.md#ReadFirewallChainRuleByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/ | Read rule by ID
[**ReadFirewallChainRuleConntrackByID**](FirewallApi.md#ReadFirewallChainRuleConntrackByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/conntrack/ | Read conntrack by ID
[**ReadFirewallChainRuleDescriptionByID**](FirewallApi.md#ReadFirewallChainRuleDescriptionByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/description/ | Read description by ID
[**ReadFirewallChainRuleDportByID**](FirewallApi.md#ReadFirewallChainRuleDportByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/dport/ | Read dport by ID
[**ReadFirewallChainRuleDstByID**](FirewallApi.md#ReadFirewallChainRuleDstByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/dst/ | Read dst by ID
[**ReadFirewallChainRuleL4protoByID**](FirewallApi.md#ReadFirewallChainRuleL4protoByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/l4proto/ | Read l4proto by ID
[**ReadFirewallChainRuleListByID**](FirewallApi.md#ReadFirewallChainRuleListByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/ | Read rule by ID
[**ReadFirewallChainRuleSportByID**](FirewallApi.md#ReadFirewallChainRuleSportByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/sport/ | Read sport by ID
[**ReadFirewallChainRuleSrcByID**](FirewallApi.md#ReadFirewallChainRuleSrcByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/src/ | Read src by ID
[**ReadFirewallChainRuleTcpflagsByID**](FirewallApi.md#ReadFirewallChainRuleTcpflagsByID) | **Get** /firewall/{name}/chain/{chain_name}/rule/{id}/tcpflags/ | Read tcpflags by ID
[**ReadFirewallChainStatsActionByID**](FirewallApi.md#ReadFirewallChainStatsActionByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/action/ | Read action by ID
[**ReadFirewallChainStatsByID**](FirewallApi.md#ReadFirewallChainStatsByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/ | Read stats by ID
[**ReadFirewallChainStatsBytesByID**](FirewallApi.md#ReadFirewallChainStatsBytesByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/bytes/ | Read bytes by ID
[**ReadFirewallChainStatsConntrackByID**](FirewallApi.md#ReadFirewallChainStatsConntrackByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/conntrack/ | Read conntrack by ID
[**ReadFirewallChainStatsDescriptionByID**](FirewallApi.md#ReadFirewallChainStatsDescriptionByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/description/ | Read description by ID
[**ReadFirewallChainStatsDportByID**](FirewallApi.md#ReadFirewallChainStatsDportByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/dport/ | Read dport by ID
[**ReadFirewallChainStatsDstByID**](FirewallApi.md#ReadFirewallChainStatsDstByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/dst/ | Read dst by ID
[**ReadFirewallChainStatsL4protoByID**](FirewallApi.md#ReadFirewallChainStatsL4protoByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/l4proto/ | Read l4proto by ID
[**ReadFirewallChainStatsListByID**](FirewallApi.md#ReadFirewallChainStatsListByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/ | Read stats by ID
[**ReadFirewallChainStatsPktsByID**](FirewallApi.md#ReadFirewallChainStatsPktsByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/pkts/ | Read pkts by ID
[**ReadFirewallChainStatsSportByID**](FirewallApi.md#ReadFirewallChainStatsSportByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/sport/ | Read sport by ID
[**ReadFirewallChainStatsSrcByID**](FirewallApi.md#ReadFirewallChainStatsSrcByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/src/ | Read src by ID
[**ReadFirewallChainStatsTcpflagsByID**](FirewallApi.md#ReadFirewallChainStatsTcpflagsByID) | **Get** /firewall/{name}/chain/{chain_name}/stats/{id}/tcpflags/ | Read tcpflags by ID
[**ReadFirewallConntrackByID**](FirewallApi.md#ReadFirewallConntrackByID) | **Get** /firewall/{name}/conntrack/ | Read conntrack by ID
[**ReadFirewallInteractiveByID**](FirewallApi.md#ReadFirewallInteractiveByID) | **Get** /firewall/{name}/interactive/ | Read interactive by ID
[**ReadFirewallListByID**](FirewallApi.md#ReadFirewallListByID) | **Get** /firewall/ | Read firewall by ID
[**ReadFirewallLoglevelByID**](FirewallApi.md#ReadFirewallLoglevelByID) | **Get** /firewall/{name}/loglevel/ | Read loglevel by ID
[**ReadFirewallServiceNameByID**](FirewallApi.md#ReadFirewallServiceNameByID) | **Get** /firewall/{name}/service-name/ | Read service-name by ID
[**ReadFirewallSessionTableByID**](FirewallApi.md#ReadFirewallSessionTableByID) | **Get** /firewall/{name}/session-table/{src}/{dst}/{l4proto}/{sport}/{dport}/ | Read session-table by ID
[**ReadFirewallSessionTableEtaByID**](FirewallApi.md#ReadFirewallSessionTableEtaByID) | **Get** /firewall/{name}/session-table/{src}/{dst}/{l4proto}/{sport}/{dport}/eta/ | Read eta by ID
[**ReadFirewallSessionTableListByID**](FirewallApi.md#ReadFirewallSessionTableListByID) | **Get** /firewall/{name}/session-table/ | Read session-table by ID
[**ReadFirewallSessionTableStateByID**](FirewallApi.md#ReadFirewallSessionTableStateByID) | **Get** /firewall/{name}/session-table/{src}/{dst}/{l4proto}/{sport}/{dport}/state/ | Read state by ID
[**ReadFirewallTypeByID**](FirewallApi.md#ReadFirewallTypeByID) | **Get** /firewall/{name}/type/ | Read type by ID
[**ReadFirewallUuidByID**](FirewallApi.md#ReadFirewallUuidByID) | **Get** /firewall/{name}/uuid/ | Read uuid by ID
[**ReplaceFirewallByID**](FirewallApi.md#ReplaceFirewallByID) | **Put** /firewall/{name}/ | Replace firewall by ID
[**ReplaceFirewallChainByID**](FirewallApi.md#ReplaceFirewallChainByID) | **Put** /firewall/{name}/chain/{chain_name}/ | Replace chain by ID
[**ReplaceFirewallChainListByID**](FirewallApi.md#ReplaceFirewallChainListByID) | **Put** /firewall/{name}/chain/ | Replace chain by ID
[**ReplaceFirewallChainRuleByID**](FirewallApi.md#ReplaceFirewallChainRuleByID) | **Put** /firewall/{name}/chain/{chain_name}/rule/{id}/ | Replace rule by ID
[**ReplaceFirewallChainRuleListByID**](FirewallApi.md#ReplaceFirewallChainRuleListByID) | **Put** /firewall/{name}/chain/{chain_name}/rule/ | Replace rule by ID
[**UpdateFirewallAcceptEstablishedByID**](FirewallApi.md#UpdateFirewallAcceptEstablishedByID) | **Patch** /firewall/{name}/accept-established/ | Update accept-established by ID
[**UpdateFirewallByID**](FirewallApi.md#UpdateFirewallByID) | **Patch** /firewall/{name}/ | Update firewall by ID
[**UpdateFirewallChainByID**](FirewallApi.md#UpdateFirewallChainByID) | **Patch** /firewall/{name}/chain/{chain_name}/ | Update chain by ID
[**UpdateFirewallChainDefaultByID**](FirewallApi.md#UpdateFirewallChainDefaultByID) | **Patch** /firewall/{name}/chain/{chain_name}/default/ | Update default by ID
[**UpdateFirewallChainListByID**](FirewallApi.md#UpdateFirewallChainListByID) | **Patch** /firewall/{name}/chain/ | Update chain by ID
[**UpdateFirewallChainRuleByID**](FirewallApi.md#UpdateFirewallChainRuleByID) | **Patch** /firewall/{name}/chain/{chain_name}/rule/{id}/ | Update rule by ID
[**UpdateFirewallChainRuleListByID**](FirewallApi.md#UpdateFirewallChainRuleListByID) | **Patch** /firewall/{name}/chain/{chain_name}/rule/ | Update rule by ID
[**UpdateFirewallConntrackByID**](FirewallApi.md#UpdateFirewallConntrackByID) | **Patch** /firewall/{name}/conntrack/ | Update conntrack by ID
[**UpdateFirewallInteractiveByID**](FirewallApi.md#UpdateFirewallInteractiveByID) | **Patch** /firewall/{name}/interactive/ | Update interactive by ID
[**UpdateFirewallListByID**](FirewallApi.md#UpdateFirewallListByID) | **Patch** /firewall/ | Update firewall by ID
[**UpdateFirewallLoglevelByID**](FirewallApi.md#UpdateFirewallLoglevelByID) | **Patch** /firewall/{name}/loglevel/ | Update loglevel by ID


# **CreateFirewallByID**
> CreateFirewallByID(ctx, name, firewall)
Create firewall by ID

Create operation of resource: firewall

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **firewall** | [**Firewall**](Firewall.md)| firewallbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainAppendByID**
> ChainAppendOutput CreateFirewallChainAppendByID(ctx, name, chainName, append)
Create append by ID

Create operation of resource: append

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **append** | [**ChainAppendInput**](ChainAppendInput.md)| appendbody object | 

### Return type

[**ChainAppendOutput**](ChainAppendOutput.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainApplyRulesByID**
> ChainApplyRulesOutput CreateFirewallChainApplyRulesByID(ctx, name, chainName)
Create apply-rules by ID

Create operation of resource: apply-rules

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

[**ChainApplyRulesOutput**](ChainApplyRulesOutput.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainByID**
> CreateFirewallChainByID(ctx, name, chainName, chain)
Create chain by ID

Create operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **chain** | [**Chain**](Chain.md)| chainbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainDeleteByID**
> CreateFirewallChainDeleteByID(ctx, name, chainName, delete)
Create delete by ID

Create operation of resource: delete

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **delete** | [**ChainDeleteInput**](ChainDeleteInput.md)| deletebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainInsertByID**
> ChainInsertOutput CreateFirewallChainInsertByID(ctx, name, chainName, insert)
Create insert by ID

Create operation of resource: insert

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **insert** | [**ChainInsertInput**](ChainInsertInput.md)| insertbody object | 

### Return type

[**ChainInsertOutput**](ChainInsertOutput.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainListByID**
> CreateFirewallChainListByID(ctx, name, chain)
Create chain by ID

Create operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chain** | [**[]Chain**](Chain.md)| chainbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainResetCountersByID**
> ChainResetCountersOutput CreateFirewallChainResetCountersByID(ctx, name, chainName)
Create reset-counters by ID

Create operation of resource: reset-counters

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

[**ChainResetCountersOutput**](ChainResetCountersOutput.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainRuleByID**
> CreateFirewallChainRuleByID(ctx, name, chainName, id, rule)
Create rule by ID

Create operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 
  **rule** | [**ChainRule**](ChainRule.md)| rulebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **CreateFirewallChainRuleListByID**
> CreateFirewallChainRuleListByID(ctx, name, chainName, rule)
Create rule by ID

Create operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **rule** | [**[]ChainRule**](ChainRule.md)| rulebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteFirewallByID**
> DeleteFirewallByID(ctx, name)
Delete firewall by ID

Delete operation of resource: firewall

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteFirewallChainByID**
> DeleteFirewallChainByID(ctx, name, chainName)
Delete chain by ID

Delete operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteFirewallChainListByID**
> DeleteFirewallChainListByID(ctx, name)
Delete chain by ID

Delete operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteFirewallChainRuleByID**
> DeleteFirewallChainRuleByID(ctx, name, chainName, id)
Delete rule by ID

Delete operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **DeleteFirewallChainRuleListByID**
> DeleteFirewallChainRuleListByID(ctx, name, chainName)
Delete rule by ID

Delete operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallAcceptEstablishedByID**
> string ReadFirewallAcceptEstablishedByID(ctx, name)
Read accept-established by ID

Read operation of resource: accept-established

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallByID**
> Firewall ReadFirewallByID(ctx, name)
Read firewall by ID

Read operation of resource: firewall

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

[**Firewall**](Firewall.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainByID**
> Chain ReadFirewallChainByID(ctx, name, chainName)
Read chain by ID

Read operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

[**Chain**](Chain.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainDefaultByID**
> string ReadFirewallChainDefaultByID(ctx, name, chainName)
Read default by ID

Read operation of resource: default

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainListByID**
> []Chain ReadFirewallChainListByID(ctx, name)
Read chain by ID

Read operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

[**[]Chain**](Chain.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleActionByID**
> string ReadFirewallChainRuleActionByID(ctx, name, chainName, id)
Read action by ID

Read operation of resource: action

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleByID**
> ChainRule ReadFirewallChainRuleByID(ctx, name, chainName, id)
Read rule by ID

Read operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

[**ChainRule**](ChainRule.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleConntrackByID**
> string ReadFirewallChainRuleConntrackByID(ctx, name, chainName, id)
Read conntrack by ID

Read operation of resource: conntrack

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleDescriptionByID**
> string ReadFirewallChainRuleDescriptionByID(ctx, name, chainName, id)
Read description by ID

Read operation of resource: description

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleDportByID**
> int32 ReadFirewallChainRuleDportByID(ctx, name, chainName, id)
Read dport by ID

Read operation of resource: dport

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleDstByID**
> string ReadFirewallChainRuleDstByID(ctx, name, chainName, id)
Read dst by ID

Read operation of resource: dst

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleL4protoByID**
> string ReadFirewallChainRuleL4protoByID(ctx, name, chainName, id)
Read l4proto by ID

Read operation of resource: l4proto

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleListByID**
> []ChainRule ReadFirewallChainRuleListByID(ctx, name, chainName)
Read rule by ID

Read operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

[**[]ChainRule**](ChainRule.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleSportByID**
> int32 ReadFirewallChainRuleSportByID(ctx, name, chainName, id)
Read sport by ID

Read operation of resource: sport

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleSrcByID**
> string ReadFirewallChainRuleSrcByID(ctx, name, chainName, id)
Read src by ID

Read operation of resource: src

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainRuleTcpflagsByID**
> string ReadFirewallChainRuleTcpflagsByID(ctx, name, chainName, id)
Read tcpflags by ID

Read operation of resource: tcpflags

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsActionByID**
> string ReadFirewallChainStatsActionByID(ctx, name, chainName, id)
Read action by ID

Read operation of resource: action

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsByID**
> ChainStats ReadFirewallChainStatsByID(ctx, name, chainName, id)
Read stats by ID

Read operation of resource: stats

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

[**ChainStats**](ChainStats.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsBytesByID**
> int32 ReadFirewallChainStatsBytesByID(ctx, name, chainName, id)
Read bytes by ID

Read operation of resource: bytes

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsConntrackByID**
> string ReadFirewallChainStatsConntrackByID(ctx, name, chainName, id)
Read conntrack by ID

Read operation of resource: conntrack

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsDescriptionByID**
> string ReadFirewallChainStatsDescriptionByID(ctx, name, chainName, id)
Read description by ID

Read operation of resource: description

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsDportByID**
> int32 ReadFirewallChainStatsDportByID(ctx, name, chainName, id)
Read dport by ID

Read operation of resource: dport

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsDstByID**
> string ReadFirewallChainStatsDstByID(ctx, name, chainName, id)
Read dst by ID

Read operation of resource: dst

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsL4protoByID**
> string ReadFirewallChainStatsL4protoByID(ctx, name, chainName, id)
Read l4proto by ID

Read operation of resource: l4proto

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsListByID**
> []ChainStats ReadFirewallChainStatsListByID(ctx, name, chainName)
Read stats by ID

Read operation of resource: stats

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 

### Return type

[**[]ChainStats**](ChainStats.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsPktsByID**
> int32 ReadFirewallChainStatsPktsByID(ctx, name, chainName, id)
Read pkts by ID

Read operation of resource: pkts

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsSportByID**
> int32 ReadFirewallChainStatsSportByID(ctx, name, chainName, id)
Read sport by ID

Read operation of resource: sport

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsSrcByID**
> string ReadFirewallChainStatsSrcByID(ctx, name, chainName, id)
Read src by ID

Read operation of resource: src

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallChainStatsTcpflagsByID**
> string ReadFirewallChainStatsTcpflagsByID(ctx, name, chainName, id)
Read tcpflags by ID

Read operation of resource: tcpflags

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallConntrackByID**
> string ReadFirewallConntrackByID(ctx, name)
Read conntrack by ID

Read operation of resource: conntrack

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallInteractiveByID**
> bool ReadFirewallInteractiveByID(ctx, name)
Read interactive by ID

Read operation of resource: interactive

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**bool**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallListByID**
> []Firewall ReadFirewallListByID(ctx, )
Read firewall by ID

Read operation of resource: firewall

### Required Parameters
This endpoint does not need any parameter.

### Return type

[**[]Firewall**](Firewall.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallLoglevelByID**
> string ReadFirewallLoglevelByID(ctx, name)
Read loglevel by ID

Read operation of resource: loglevel

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallServiceNameByID**
> string ReadFirewallServiceNameByID(ctx, name)
Read service-name by ID

Read operation of resource: service-name

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallSessionTableByID**
> SessionTable ReadFirewallSessionTableByID(ctx, name, src, dst, l4proto, sport, dport)
Read session-table by ID

Read operation of resource: session-table

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **src** | **string**| ID of src | 
  **dst** | **string**| ID of dst | 
  **l4proto** | **string**| ID of l4proto | 
  **sport** | **int32**| ID of sport | 
  **dport** | **int32**| ID of dport | 

### Return type

[**SessionTable**](SessionTable.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallSessionTableEtaByID**
> int32 ReadFirewallSessionTableEtaByID(ctx, name, src, dst, l4proto, sport, dport)
Read eta by ID

Read operation of resource: eta

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **src** | **string**| ID of src | 
  **dst** | **string**| ID of dst | 
  **l4proto** | **string**| ID of l4proto | 
  **sport** | **int32**| ID of sport | 
  **dport** | **int32**| ID of dport | 

### Return type

**int32**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallSessionTableListByID**
> []SessionTable ReadFirewallSessionTableListByID(ctx, name)
Read session-table by ID

Read operation of resource: session-table

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

[**[]SessionTable**](SessionTable.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallSessionTableStateByID**
> string ReadFirewallSessionTableStateByID(ctx, name, src, dst, l4proto, sport, dport)
Read state by ID

Read operation of resource: state

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **src** | **string**| ID of src | 
  **dst** | **string**| ID of dst | 
  **l4proto** | **string**| ID of l4proto | 
  **sport** | **int32**| ID of sport | 
  **dport** | **int32**| ID of dport | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallTypeByID**
> string ReadFirewallTypeByID(ctx, name)
Read type by ID

Read operation of resource: type

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReadFirewallUuidByID**
> string ReadFirewallUuidByID(ctx, name)
Read uuid by ID

Read operation of resource: uuid

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 

### Return type

**string**

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReplaceFirewallByID**
> ReplaceFirewallByID(ctx, name, firewall)
Replace firewall by ID

Replace operation of resource: firewall

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **firewall** | [**Firewall**](Firewall.md)| firewallbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReplaceFirewallChainByID**
> ReplaceFirewallChainByID(ctx, name, chainName, chain)
Replace chain by ID

Replace operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **chain** | [**Chain**](Chain.md)| chainbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReplaceFirewallChainListByID**
> ReplaceFirewallChainListByID(ctx, name, chain)
Replace chain by ID

Replace operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chain** | [**[]Chain**](Chain.md)| chainbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReplaceFirewallChainRuleByID**
> ReplaceFirewallChainRuleByID(ctx, name, chainName, id, rule)
Replace rule by ID

Replace operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 
  **rule** | [**ChainRule**](ChainRule.md)| rulebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **ReplaceFirewallChainRuleListByID**
> ReplaceFirewallChainRuleListByID(ctx, name, chainName, rule)
Replace rule by ID

Replace operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **rule** | [**[]ChainRule**](ChainRule.md)| rulebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallAcceptEstablishedByID**
> UpdateFirewallAcceptEstablishedByID(ctx, name, acceptEstablished)
Update accept-established by ID

Update operation of resource: accept-established

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **acceptEstablished** | **string**| If Connection Tracking is enabled, all packets belonging to ESTABLISHED connections will be forwarded automatically. Default is ON. | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallByID**
> UpdateFirewallByID(ctx, name, firewall)
Update firewall by ID

Update operation of resource: firewall

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **firewall** | [**Firewall**](Firewall.md)| firewallbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallChainByID**
> UpdateFirewallChainByID(ctx, name, chainName, chain)
Update chain by ID

Update operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **chain** | [**Chain**](Chain.md)| chainbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallChainDefaultByID**
> UpdateFirewallChainDefaultByID(ctx, name, chainName, default_)
Update default by ID

Update operation of resource: default

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **default_** | **string**| Default action if no rule matches in the ingress chain. Default is DROP. | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallChainListByID**
> UpdateFirewallChainListByID(ctx, name, chain)
Update chain by ID

Update operation of resource: chain

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chain** | [**[]Chain**](Chain.md)| chainbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallChainRuleByID**
> UpdateFirewallChainRuleByID(ctx, name, chainName, id, rule)
Update rule by ID

Update operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **id** | **int32**| ID of id | 
  **rule** | [**ChainRule**](ChainRule.md)| rulebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallChainRuleListByID**
> UpdateFirewallChainRuleListByID(ctx, name, chainName, rule)
Update rule by ID

Update operation of resource: rule

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **chainName** | **string**| ID of chain_name | 
  **rule** | [**[]ChainRule**](ChainRule.md)| rulebody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallConntrackByID**
> UpdateFirewallConntrackByID(ctx, name, conntrack)
Update conntrack by ID

Update operation of resource: conntrack

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **conntrack** | **string**| Enables the Connection Tracking module. Mandatory if connection tracking rules are needed. Default is ON. | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallInteractiveByID**
> UpdateFirewallInteractiveByID(ctx, name, interactive)
Update interactive by ID

Update operation of resource: interactive

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **interactive** | **bool**| Interactive mode applies new rules immediately; if &#39;false&#39;, the command &#39;apply-rules&#39; has to be used to apply all the rules at once. Default is TRUE. | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallListByID**
> UpdateFirewallListByID(ctx, firewall)
Update firewall by ID

Update operation of resource: firewall

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **firewall** | [**[]Firewall**](Firewall.md)| firewallbody object | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **UpdateFirewallLoglevelByID**
> UpdateFirewallLoglevelByID(ctx, name, loglevel)
Update loglevel by ID

Update operation of resource: loglevel

### Required Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **ctx** | **context.Context** | context for authentication, logging, cancellation, deadlines, tracing, etc.
  **name** | **string**| ID of name | 
  **loglevel** | **string**| Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE) | 

### Return type

 (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

