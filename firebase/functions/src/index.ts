import { auth, initializeApp } from 'firebase-admin';
import * as functions from 'firebase-functions';
import fetch from 'node-fetch';

initializeApp();
const _auth = auth();

/// User used to get an JWT from
export const registerUser = functions.https.onRequest(async (request, response) => {
    await _auth.createUser({
        displayName: 'Max Mustermann',
        email: 'max-mustermann@test.test',
        emailVerified: true,
        password: 'i like ice cream',
        uid: request.body.uid ?? 'max-mustermann-uid'
    });

    response.status(200).send();
});


export const getAuthToken = functions.https.onRequest(async (request, response) => {
    // customToken is not the same as the normal client token (idToken) as it has no "kid" claim.
    const customToken = await _auth.createCustomToken(request.body.uid ?? 'max-mustermann-uid');
    const idToken = await getIdTokenFromCustomToken(customToken);

    response.send(idToken);
});


async function getIdTokenFromCustomToken(customToken: string): Promise<string> {
    // From https://console.firebase.google.com/project/[projectId]/settings/general (web api key)
    // firebase namespace is reserved so i use fbase
    const apiKey = functions.config().fbase.api_key;
    const url = `https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken?key=${apiKey}`;
    const data = {
        token: customToken,
        returnSecureToken: true
    };

    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify(data)
    });

    // Just has to work lol
    const json = await response.json();
    return json.idToken;
}
