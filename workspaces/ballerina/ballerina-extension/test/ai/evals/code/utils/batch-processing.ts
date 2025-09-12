// Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

import { TestUseCase, UsecaseResult } from '../types';
import { executeSingleTestCase } from './test-execution';
import { convertTestResultToUsecaseResult, createFailedUsecaseResult } from '../result-management/result-conversion';
import { TIMING } from './constants';

/**
 * Processes a single batch of test cases in parallel
 */
export async function processSingleBatch(
    batch: readonly TestUseCase[], 
    batchNumber: number
): Promise<readonly UsecaseResult[]> {
    console.log(`\n📋 Processing batch ${batchNumber}: ${batch.map(uc => uc.id).join(', ')}`);

    const batchPromises = batch.map(useCase => 
        executeSingleTestCase(useCase)
    );
    
    const batchResults = await Promise.allSettled(batchPromises);
    const usecaseResults: UsecaseResult[] = [];
    
    for (let j = 0; j < batchResults.length; j++) {
        const settledResult = batchResults[j];
        const useCase = batch[j];
        
        let usecaseResult: UsecaseResult;
        
        if (settledResult.status === 'fulfilled') {
            usecaseResult = convertTestResultToUsecaseResult(settledResult.value);
        } else {
            console.error(`❌ Test case ${useCase.id} failed:`, settledResult.reason);
            usecaseResult = createFailedUsecaseResult(useCase, settledResult.reason);
        }
        
        usecaseResults.push(usecaseResult);
    }
    
    return usecaseResults;
}

/**
 * Handles inter-batch delays and monitoring
 */
export async function handleBatchDelay(
    currentIndex: number, 
    totalUseCases: number, 
    maxConcurrency: number
): Promise<void> {
    if (currentIndex + maxConcurrency < totalUseCases) {
        console.log(`⏳ Waiting ${TIMING.INTER_BATCH_DELAY}ms before next batch...`);
        await new Promise(resolve => setTimeout(resolve, TIMING.INTER_BATCH_DELAY));
    }
}

/**
 * Utility function to wait for a specified duration
 */
export function wait(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}