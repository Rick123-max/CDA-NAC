# To Know:
## Splunk Forwarder Config Structure
- Heavy Forwarder reads transforms.conf and props.conf
- Universal reads inputs.conf and outputs.conf

## Vulnerability Mitigations
## MITRE ATACK T-CODES

## Data Normalization
### Filters, GROK, mutate
#### Logstash Filter
<img width="176" height="153" alt="image" src="https://github.com/user-attachments/assets/8b2f7b17-2ff0-4d50-9242-fa7a389098b7" />
#### Dissect filter
<img width="380" height="199" alt="image" src="https://github.com/user-attachments/assets/b939b28a-f7ac-482c-9cc5-aa005577eeba" />
#### GROK Filter
<img width="381" height="170" alt="image" src="https://github.com/user-attachments/assets/196184fe-08a3-42cd-a498-8da01498eac5" />









# To Do:
## Kibana query using Lucene and KQL
### Lucene
- The legacy functions maintained by Lucene are fuzzy searches, proximity searches, and Regular Expressions (RegEx) searches.
#### Free Text
<img width="818" height="130" alt="517013696-2214ad93-87cb-445b-abaa-3d9c900f5464" src="https://github.com/user-attachments/assets/8a72bc9d-ea25-455c-be4c-ee6c9678fe29" />
#### Field-Value Pairs
<img width="819" height="124" alt="517013817-9354db8b-121a-4679-9e1b-f3125d3d7947" src="https://github.com/user-attachments/assets/d784c63e-0f98-437f-be1d-9f6df0126f2c" />
#### Ranges
<img width="818" height="122" alt="517014004-4628f4ca-c903-46c1-bb37-5d2e2f35132f" src="https://github.com/user-attachments/assets/e4645f97-61ac-444f-b7a8-7daf89374b67" />
#### Wildcard
<img width="822" height="124" alt="517014429-0c813003-05d4-492a-842e-4065652f8274" src="https://github.com/user-attachments/assets/a24a69de-e195-41d0-ae32-902ac54ca6f6" />
<img width="819" height="122" alt="517014439-599e0923-b5d6-4936-8ae7-e7f9d0c75099" src="https://github.com/user-attachments/assets/b8a557c9-ab89-44f3-a2e9-e6d97911250f" />
#### Fuzzy
<img width="878" height="115" alt="517016436-31e052d1-219f-4896-abbc-081adb393e05" src="https://github.com/user-attachments/assets/ff067dea-bd14-46ac-96fe-a36146a7c96f" />
#### Proximity
<img width="886" height="116" alt="517016653-7fad8f38-a88c-4710-ba87-7a506f1d89ca" src="https://github.com/user-attachments/assets/bab383e9-c2e3-4d8e-af1d-7c89c0c8c851" />
#### REGEX
<img width="886" height="115" alt="517016810-3f3de7d9-32e2-4f90-87ae-6b56237c66ac" src="https://github.com/user-attachments/assets/352f9f30-3e3c-4c0c-bade-455359d5eacf" />
#### BOOLEAN
- `(field1:valueA OR field1:valueB) AND field2:valueC AND NOT field3:valueD`

### KQL
#### Free Text
<img width="816" height="122" alt="517019007-586fc7ff-8a7b-4c54-baaf-44c760cb4ab5" src="https://github.com/user-attachments/assets/da04ce0d-5e62-4b9c-9b17-2a8cb142c482" />
#### Terms Queries
<img width="832" height="133" alt="517019076-ac4b3e37-a1ff-441b-932f-ea190259b3ff" src="https://github.com/user-attachments/assets/6f8ef736-a3ee-4fa9-8227-e4eff57233b9" />
#### Wildcard
<img width="825" height="125" alt="517019350-fd1bfd6b-9f04-44ae-b7b7-103dfc83110e" src="https://github.com/user-attachments/assets/4ee6a453-ed79-4643-b048-20eb70f201e8" />
<img width="825" height="125" alt="517019350-fd1bfd6b-9f04-44ae-b7b7-103dfc83110e" src="https://github.com/user-attachments/assets/57634a26-55dd-43d3-ae68-4a277f7d7264" />
#### Exists
<img width="813" height="121" alt="517019575-20856b1d-dbc3-4335-9e8a-9589e3db177f" src="https://github.com/user-attachments/assets/ff8c950b-3fde-4cfe-b4bf-7d2cb467f118" />
#### Boolean
<img width="883" height="108" alt="517020769-65c585e1-2e8f-41cf-bd19-a7845ef696d5" src="https://github.com/user-attachments/assets/14190204-cb04-4e18-9a7e-6ede8cad4e57" />
#### Ranges
<img width="879" height="115" alt="517020957-fbe45552-5c81-441f-aa30-f546339c0126" src="https://github.com/user-attachments/assets/d2ecaa34-afbd-4152-9b58-7d9850665ce2" />
#### Date Ranges
<img width="874" height="100" alt="517021020-4f532683-ea62-43f5-9acc-10f20e5ad44a" src="https://github.com/user-attachments/assets/58acd088-80de-4955-bdda-12236ecf9269" />
<img width="876" height="110" alt="517021034-1296d628-0f10-4c63-ae5c-a905f94cf271" src="https://github.com/user-attachments/assets/bd71fcf6-c9d8-411e-8f48-35d53a1f43f0" />
<img width="871" height="101" alt="517021084-72e320b2-054c-48b9-86e2-b9cc3ee1ced2" src="https://github.com/user-attachments/assets/41dd8b7d-65cc-4799-a51b-81447daae04d" />
<img width="876" height="106" alt="517021105-99271c9a-5be0-4215-9662-fdc471e49662" src="https://github.com/user-attachments/assets/b98748ef-08fe-482c-81b9-682780bd3454" />
#### Nested Fields
<img width="877" height="104" alt="517021255-5ded280a-d261-4245-abd3-12e61aedd5bb" src="https://github.com/user-attachments/assets/c3fca442-d918-4956-8487-30235299acf0" />
<img width="883" height="111" alt="517021286-757bd9c4-7e20-45f0-96a8-8c4eb18adb8a" src="https://github.com/user-attachments/assets/5955deb6-ab00-4b6e-a04e-611893a63ec1" />

## Splunk Query (SPL)
- `field=value`
- `field1=valueA OR field2=valueB`
- `(field1=valueA OR field2=valueB) AND field3=valueC`
- `index=* dimension="length" units="feet" | eval value_in_meters=value*3.28`+


## ILM Policy Change
- Hot Storage
  - Hot storage solutions are designed for data that must be quickly processed and searched.
  - Typically, a hot storage solution stores the most recent and relevant data with the time frame dictated by the mission partner and system resources.
  - Server nodes hosting data in the hot storage tier generally require additional compute resources such as increased Central Processing Unit (CPU), Random Access Memory (RAM), and fast disk arrays to meet performance needs.
  - An example of a common policy is to store 1 month of events in a hot storage solution.
- Warm Storage
  - Warm storage solutions are used to store data that is queried less frequently than recently indexed data kept in hot storage.
  - Nodes hosting data in the warm storage tier have lower performance requirements than hot storage nodes. Therefore, this hardware is generally less expensive.
  - This solution provides organizations with an opportunity to store data over longer periods and reduce cost associated with high-performance compute nodes.
- Cold Storage
  - Under the cold storage solution, older data is retained in an inspection platform that is still searchable but is considerably slower than hot or warm tiers.
  - This solution prioritizes bulk storage of data over search performance.
  - The mission partner or organization should make a determination for the length of time that different sources should be stored in cold storage.










