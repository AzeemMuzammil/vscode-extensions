/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { AuthCredentials, AuthSessionStore, LoginMethod } from "@wso2/ballerina-core";
import { extension } from "../../BalExtensionContext";
import { getDevantCredentials } from "./auth";

export const AUTH_SESSION_STORE_KEY = 'BallerinaAuthSessionStore';

// ==================================
// Multi-Session Auth Management Utils
// ==================================
export const setCurrentActiveFlowInSecrets = async (loginMethod: LoginMethod): Promise<void> => {
    let store: AuthSessionStore;

    const storeJson = await extension.context.secrets.get(AUTH_SESSION_STORE_KEY);
    if (storeJson) {
        try {
            store = JSON.parse(storeJson) as AuthSessionStore;
        } catch (error) {
            store = { sessions: {} };
        }
    } else {
        store = { sessions: {} };
    }

    store.currentActiveFlow = loginMethod;
    store.metadata = {
        ...store.metadata,
        lastUpdated: new Date().toISOString()
    };

    await extension.context.secrets.store(AUTH_SESSION_STORE_KEY, JSON.stringify(store));
};

export const getAuthCredentialsFromSecrets = async (): Promise<AuthCredentials | undefined> => {
    const storeJson = await extension.context.secrets.get(AUTH_SESSION_STORE_KEY);
    if (!storeJson) {
        return undefined;
    }

    try {
        const store = JSON.parse(storeJson) as AuthSessionStore;
        if (!store.currentActiveFlow) {
            return undefined;
        }

        // If current flow is devant, return from environment
        if (store.currentActiveFlow === LoginMethod.DEVANT_ENV) {
            return await getDevantCredentials();
        }

        // For SSO and Anthropic, return from stored sessions
        return store.sessions[store.currentActiveFlow];
    } catch (error) {
        console.error('Error getting auth credentials:', error);
        return undefined;
    }
};

export const storeAuthCredentialsInSecrets = async (credentials: AuthCredentials): Promise<void> => {
    let store: AuthSessionStore;

    const storeJson = await extension.context.secrets.get(AUTH_SESSION_STORE_KEY);
    if (storeJson) {
        try {
            store = JSON.parse(storeJson) as AuthSessionStore;
        } catch (error) {
            store = { sessions: {} };
        }
    } else {
        store = { sessions: {} };
    }

    store.sessions[credentials.loginMethod] = credentials;
    store.metadata = {
        ...store.metadata,
        lastUpdated: new Date().toISOString()
    };

    await extension.context.secrets.store(AUTH_SESSION_STORE_KEY, JSON.stringify(store));
};

export const clearAuthCredentialsFromSecrets = async (): Promise<void> => {
    await extension.context.secrets.delete(AUTH_SESSION_STORE_KEY);
};
