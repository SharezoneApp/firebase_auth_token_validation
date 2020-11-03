The repo needs:
* A Firebase project
* an `.env` file with the follwing values:
  * FIREBASE_API_TOKEN (Is the `apiKey` from a `firebaseConfig` - Can be obtained by creating a Web-App and going to "Project Settings > General") 
  * FIREBASE_FUNCTIONS_BASE_URL (the base url of the deployed firebase cloud functions e.g. "https://us-central1-my-project.cloudfunctions.net". MUST NOT contain a slash "/" at the end)
  * FIREBASE_PROJECT_ID (The Firebase Project Id)

With the `.env`-file: 
* Cloud Functions can be deployed via `./deploy_functions.sh` (make sure to run `npm install` in the functions directory first)
* Tests (including E2E tests) can be run via `./run_all_tests.sh`