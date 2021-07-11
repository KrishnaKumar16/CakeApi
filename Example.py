from CakeApiUtilities import CreateApiCollection

demoApiCollection = CreateApiCollection(baseUrl="https://reqres.in/")
demoApiCollection.hitTheGetRequest(url = "/api/users?page=2").setCollectionVariable("sample", "sample")
demoApiCollection.closeSession()
demoApiCollection.createNewSession()
demoApiCollection.closeSession()
