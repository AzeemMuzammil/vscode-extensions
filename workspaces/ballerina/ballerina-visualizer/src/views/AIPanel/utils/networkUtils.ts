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

import { AIMachineEventType, LoginMethod } from "@wso2/ballerina-core";

interface FetchWithAuthParams {
    url: string;
    method: "GET" | "POST" | "PUT" | "DELETE";
    body?: any;
    rpcClient: any;
}

// Global controller for aborting requests
let controller: AbortController | null = null;

export const fetchWithAuth = async ({
    url,
    method,
    body,
    rpcClient,
}: FetchWithAuthParams): Promise<Response> => {
    controller?.abort();

    controller = new AbortController();

    // Get authentication credentials to determine method
    let authCredentials;
    try {
        authCredentials = await rpcClient.getAiPanelRpcClient().getAuthCredentials();
    } catch (error) {
        if (isErrorWithMessage(error) && error?.message === "TOKEN_EXPIRED") {
            rpcClient.sendAIStateEvent(AIMachineEventType.SILENT_LOGOUT);
            return;
        }
        throw error;
    }

    if (!authCredentials) {
        throw new Error("No authentication credentials available");
    }

    const makeRequest = async (credentials: any): Promise<Response> => {
        const headers: Record<string, string> = {
            "Content-Type": "application/json",
        };

        // Set authentication headers based on login method
        if (credentials.loginMethod === LoginMethod.BI_INTEL) {
            headers["Authorization"] = `Bearer ${credentials.secrets.accessToken}`;
        } else if (credentials.loginMethod === LoginMethod.DEVANT_ENV) {
            headers["api-key"] = credentials.secrets.apiKey;
            headers["x-Authorization"] = credentials.secrets.stsToken;
        } else {
            throw new Error(`Unsupported login method: ${credentials.loginMethod}`);
        }

        return fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
            signal: controller!.signal,
        });
    };

    let response = await makeRequest(authCredentials);

    // Handle token expiration (only for BI_INTEL flow)
    if (response.status === 401 && authCredentials.loginMethod === LoginMethod.BI_INTEL) {
        const newToken = await rpcClient.getAiPanelRpcClient().getRefreshedAccessToken();
        if (newToken) {
            // Update credentials with new token
            const updatedCredentials = {
                ...authCredentials,
                secrets: {
                    ...authCredentials.secrets,
                    accessToken: newToken
                }
            };
            response = await makeRequest(updatedCredentials);
        }
    }

    return response;
}

// Function to abort the fetch request
export function abortFetchWithAuth() {
    if (controller) {
        controller.abort();
        controller = null;
    }
}

function isErrorWithMessage(error: unknown): error is { message: string } {
    return typeof error === 'object' && error !== null && 'message' in error;
}
