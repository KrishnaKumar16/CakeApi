from CakeApiUtilities import CreateApiCollection

demoApiCollection = CreateApiCollection(collectionName="Demo Collection",
                                        baseUrl="https://reqres.in")
demoApiCollection.hitTheGetRequest(endPoint="/api/users?page=2")
demoApiCollection.validateStatusCodeIs200()
demoApiCollection.SetValueFromResponseToTheCollectionVariale("FirstName", "['data'][0]['first_name']")
demoApiCollection.validateTheResponseValue(expectedValue="Michael",
                                           responseDictPath="['data'][0]['first_name']")
demoApiCollection.hitThePostRequest(endPoint="/api/users",
                                    data=dict(name="morpheus", job="leader"))
demoApiCollection.validateStatusCodeIs201()
demoApiCollection.validateTheResponseValue(expectedValue="leader",
                                           responseDictPath="['job']")
demoApiCollection.closeSession()
