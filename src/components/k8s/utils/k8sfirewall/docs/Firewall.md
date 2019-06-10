# Firewall

## Properties
Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Name** | **string** | Name of the firewall service | [optional] [default to null]
**Uuid** | **string** | UUID of the Cube | [optional] [default to null]
**Type_** | **string** | Type of the Cube (TC, XDP_SKB, XDP_DRV) | [optional] [default to null]
**ServiceName** | **string** |  | [optional] [default to null]
**Loglevel** | **string** | Defines the logging level of a service instance, from none (OFF) to the most verbose (TRACE) | [optional] [default to null]
**Conntrack** | **string** | Enables the Connection Tracking module. Mandatory if connection tracking rules are needed. Default is ON. | [optional] [default to null]
**AcceptEstablished** | **string** | If Connection Tracking is enabled, all packets belonging to ESTABLISHED connections will be forwarded automatically. Default is ON. | [optional] [default to null]
**Interactive** | **bool** | Interactive mode applies new rules immediately; if &#39;false&#39;, the command &#39;apply-rules&#39; has to be used to apply all the rules at once. Default is TRUE. | [optional] [default to null]
**SessionTable** | [**[]SessionTable**](SessionTable.md) |  | [optional] [default to null]
**Chain** | [**[]Chain**](Chain.md) |  | [optional] [default to null]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


