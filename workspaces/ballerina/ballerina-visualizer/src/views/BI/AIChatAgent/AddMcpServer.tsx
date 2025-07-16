/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 LLC. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */

import { useEffect, useRef, useState } from "react";
import styled from "@emotion/styled";
import { FlowNode } from "@wso2/ballerina-core";
import { useRpcContext } from "@wso2/ballerina-rpc-client";
import { ActionButtons, Button, Codicon, ThemeColors, Dropdown } from "@wso2/ui-toolkit";
import { RelativeLoader } from "../../../components/RelativeLoader";
import { addMcpServerToAgentNode, updateMcpServerToAgentNode, findAgentNodeFromAgentCallNode, getAgentFilePath } from "./utils";
import { TextField, CheckBox } from '@wso2/ui-toolkit';

const NameContainer = styled.div`
    display: flex;
    flex-direction: row;
`;

export const ContentWrapper = styled.div`
    display: flex;
    flex-direction: column;
    gap: 10px;
`;

const Container = styled.div`
    padding: 16px;
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 100%;
    box-sizing: border-box;
`;

const LoaderContainer = styled.div`
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100%;
`;

const Description = styled.div`
    font-size: var(--vscode-font-size);
    color: ${ThemeColors.ON_SURFACE_VARIANT};
    margin-bottom: 8px;
`;

const Column = styled.div`
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
    overflow-y: auto;
`;

const Row = styled.div`
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
`;

const Title = styled.div`
    font-size: 14px;
    font-family: GilmerBold;
`;

const ToolItem = styled.div<{ isSelected?: boolean }>`
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 5px;
    padding: 5px;
    border: 1px solid
        ${(props: { isSelected: boolean }) => (props.isSelected ? ThemeColors.PRIMARY : ThemeColors.OUTLINE_VARIANT)};
    border-radius: 5px;
    height: 36px;
    cursor: "pointer";
    font-size: 14px;
    &:hover {
        background-color: ${ThemeColors.PRIMARY_CONTAINER};
        border: 1px solid ${ThemeColors.PRIMARY};
    }
`;

const PrimaryButton = styled(Button)`
    appearance: "primary";
`;

const HighlightedButton = styled.div`
    margin-top: 10px;
    width: 100%;
    display: flex;
    flex-direction: row;
    justify-content: center;
    align-items: flex-start;
    gap: 8px;
    padding: 6px 2px;
    color: ${ThemeColors.PRIMARY};
    border: 1px dashed ${ThemeColors.PRIMARY};
    border-radius: 5px;
    cursor: pointer;
    &:hover {
        border: 1px solid ${ThemeColors.PRIMARY};
        background-color: ${ThemeColors.PRIMARY_CONTAINER};
    }
`;

const Footer = styled.div`
    position: fixed;
    bottom: 0;
    left: 0;

    width: 100%;
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    padding: 16px;
    background-color: ${ThemeColors.SURFACE_DIM};
    margin-top: auto;
`;

const ToolsContainer = styled.div`
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 12px;
    padding: 12px;
    border: 1px solid ${ThemeColors.OUTLINE_VARIANT};
    border-radius: 8px;
`;

const ToolsHeader = styled.div`
    display: flex;
    flex-direction: row;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
`;

const ToolsTitle = styled.div`
    font-size: 14px;
    font-family: GilmerBold;
    color: ${ThemeColors.ON_SURFACE};
`;

const ToolCheckboxContainer = styled.div`
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 200px;
    overflow-y: auto;
`;

const ToolCheckboxItem = styled.div`
    display: flex;
    flex-direction: row;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
`;

const ErrorMessage = styled.div`
    color: ${ThemeColors.ERROR};
    font-size: 12px;
    margin-top: 4px;
`;

const LoadingMessage = styled.div`
    color: ${ThemeColors.ON_SURFACE_VARIANT};
    font-size: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
`;

const CheckboxIcon = styled.div<{ visible: boolean }>`
    width: 10px;
    height: 10px;
    opacity: ${props => props.visible ? 1 : 0};
    transition: opacity 0.2s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    
    /* SVG checkmark */
    &::after {
        content: '';
        width: 8px;
        height: 8px;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill='white' d='M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z'/%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: center;
        background-size: contain;
    }
`;

interface Tool {
    name: string;
    description?: string;
}

interface AddToolProps {
    editMode?: boolean;
    name?: string;
    agentCallNode: FlowNode;
    onAddMcpServer: () => void;
    onSave?: () => void;
    onBack?: () => void;
}

export function AddMcpServer(props: AddToolProps): JSX.Element {
    const { agentCallNode, onAddMcpServer, onSave, editMode = false } = props;
    console.log(">>> Add Mcp Server props", props);
    const { rpcClient } = useRpcContext();
    const [mcpToolkitCount, setMcpToolkitCount] = useState<number>(1);
    const [agentNode, setAgentNode] = useState<FlowNode | null>(null);
    const [existingTools, setExistingTools] = useState<string[]>([]);
    const [toolsStringList, setToolsStringList] = useState<string>("");
    const [selectedTool, setSelectedTool] = useState<string | null>(null);
    const [urlError, setUrlError] = useState<string>("");
    const [nameError, setNameError] = useState<string>("");
    const [mcpToolResponse, setMcpToolResponse] = useState<FlowNode>(null);

    const [serviceUrl, setServiceUrl] = useState("");
    const [errorInputs, setErrorInputs] = useState(false);
    const [configs, setConfigs] = useState({});
    const [toolSelection, setToolSelection] = useState("All");
    const [name, setName] = useState(props.name || "");
    
    // New state for MCP server tools
    const [mcpTools, setMcpTools] = useState<Tool[]>([]);
    const [selectedMcpTools, setSelectedMcpTools] = useState<Set<string>>(new Set());
    const [loadingMcpTools, setLoadingMcpTools] = useState(false);
    const [mcpToolsError, setMcpToolsError] = useState<string>("");

    const [loading, setLoading] = useState<boolean>(false);
    const [savingForm, setSavingForm] = useState<boolean>(false);

    const agentFilePath = useRef<string>("");

    const handleAddNewMcpServer = () => {
        onAddMcpServer();
    }

    const handleBack = () => {
        props.onBack?.();
    };

    useEffect(() => {
        initPanel();
    }, [agentCallNode]);

    // Effect to fetch MCP tools when serviceUrl changes and toolSelection is "Selected"
    useEffect(() => {
        if (toolSelection === "Selected" && serviceUrl.trim()) {
            fetchMcpTools();
        } else {
            // Clear tools when not in selected mode or no URL
            setMcpTools([]);
            setSelectedMcpTools(new Set());
            setMcpToolsError("");
        }
    }, [toolSelection, serviceUrl]);

    const fetchAgentNode = async () => {
        const agentNode = await findAgentNodeFromAgentCallNode(agentCallNode, rpcClient);
        setAgentNode(agentNode);

        const mcpToolResponse = await rpcClient
            .getBIDiagramRpcClient()
            .getNodeTemplate({
                position: { line: 0, offset: 0 },
                filePath: agentFilePath.current,
                id: {
                    node: "NEW_CONNECTION",
                    org: "ballerina",
                    module: "mcp",
                    "packageName": "mcp",
                    version: "0.4.2",
                    symbol: "init",
                    object: "Client"
                }
            });
        // console.log(">>> mcpToolResponse", mcpToolResponse);
        setMcpToolResponse(mcpToolResponse.flowNode)
        console.log(">>> response getSourceCode with template ", { mcpToolResponse });
        if (agentNode?.properties?.tools?.value) {
            const toolsString = agentNode.properties.tools.value.toString();
            const mcpToolkits = extractMcpToolkits(toolsString);
            console.log(">>> toolsString", toolsString);
            console.log(">>> mcpToolkits", mcpToolkits);
            if (mcpToolkits.length > 0) {
                setMcpToolkitCount(mcpToolkits.length + 1);
            }
            setToolsStringList(toolsString);

            if (name.trim() !== "") {
                const tools = props.agentCallNode?.metadata?.data?.tools || [];
                console.log(">>> tools", tools);
                if (tools.length > 0) {
                    const matchingTool = tools.find(tool => tool.name.includes(name));
                    console.log(">>> matching tool", matchingTool);
                    console.log(">>> existing mcp toolkit", toolsString);
                    
                    if (matchingTool) {
                        // Escape special regex characters in the tool name
                        const escapedToolName = matchingTool.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                        
                        // Improved regex pattern to capture URL and permittedTools
                        const mcpToolkitPattern = `McpToolKit\\(\\s*"([^"]+)"\\s*,\\s*permittedTools\\s*=\\s*(\\([^)]*\\)|\\[[^\\]]*\\])\\s*,\\s*info\\s*=\\s*\\{[^}]*name:\\s*"${escapedToolName}[^"]*"`;
                        const mcpToolkitRegex = new RegExp(mcpToolkitPattern);
                        
                        const match = toolsString.match(mcpToolkitRegex);
                        console.log(">>> regex match", match);
                        
                        if (match) {
                            // Extract the URL (first capture group)
                            const url = match[1];
                            setServiceUrl(url);
                            
                            const permittedToolsStr = match[2];
                            if (permittedToolsStr && permittedToolsStr.trim() !== "()") {
                                setToolSelection("Selected");
                                const toolNames = permittedToolsStr
                                    .replace(/[\[\]()]/g, '')
                                    .split(',')
                                    .map(t => t.trim().replace(/"/g, ''))
                                    .filter(t => t !== '');
                                setSelectedMcpTools(new Set(toolNames));
                            } else {
                                setToolSelection("All");
                                setSelectedMcpTools(new Set());
                            }
                        }
                    }
                }
            }
        }
    };

    const initPanel = async () => {
        setLoading(true);
        // get agent file path
        agentFilePath.current = await getAgentFilePath(rpcClient);
        // fetch tools and agent node
        await fetchExistingTools();
        await fetchAgentNode();
        setLoading(false);
    };

    useEffect(() => {
        
    }, [name, props.agentCallNode?.metadata?.data?.tools, toolsStringList]);

    const extractMcpToolkits = (toolsString: string): string[] => {
        const mcpToolkits: string[] = [];
        const regex = /check new ai:McpToolKit/g;
        const matches = toolsString.match(regex);
        
        if (matches) {
            mcpToolkits.push(...Array(matches.length).fill("MCP Server"));
        }
        
        return mcpToolkits;
    };
    
    const fetchExistingTools = async () => {
        const existingTools = await rpcClient.getAIAgentRpcClient().getTools({ filePath: agentFilePath.current });
        console.log(">>> existing tools", existingTools);
        setExistingTools(existingTools.tools);
    };

    const fetchMcpTools = async () => {
        if (!serviceUrl.trim()) {
            return;
        }

        setLoadingMcpTools(true);
        setMcpToolsError("");
        setMcpTools([]);
        // Don't clear selected tools in edit mode
        if (!editMode) {
            setSelectedMcpTools(new Set());
        }

        try {
            // Check if getMcpTools method exists in the RPC client
            const languageServerClient = rpcClient.getAIAgentRpcClient();
            
            if (typeof languageServerClient.getMcpTools === 'function') {
                // Use the actual RPC method if it exists
                console.log(">>> Fetching MCP tools from server");
                const response = await languageServerClient.getMcpTools({ 
                    serviceUrl: serviceUrl.trim(),
                    configs: configs
                });
                
                console.log(">>> MCP tools response", response);
                
                if (response.tools && Array.isArray(response.tools)) {
                    setMcpTools(response.tools);
                } else {
                    setMcpToolsError("No tools found in MCP server response");
                }
            }
        } catch (error) {
            console.error(">>> Error fetching MCP tools", error);
            setMcpToolsError(`Failed to fetch tools from MCP server: ${error || 'Unknown error'}`);
        } finally {
            setLoadingMcpTools(false);
        }
    };

    const handleToolSelectionChange = (toolName: string, isSelected: boolean) => {
        const newSelectedTools = new Set(selectedMcpTools);
        if (isSelected) {
            newSelectedTools.add(toolName);
        } else {
            newSelectedTools.delete(toolName);
        }
        setSelectedMcpTools(newSelectedTools);
    };

    const validateUrl = (url: string): string => {
        if (!url.trim()) {
            return '';
        }

        try {
            const urlObj = new URL(url);
            // Check if protocol is http or https
            if (!['http:', 'https:'].includes(urlObj.protocol)) {
                return 'URL must use HTTP or HTTPS protocol';
            }
            return '';
        } catch (error) {
            return 'Please enter a valid URL (e.g., http://example.com)';
        }
    };

    const handleServiceUrlChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newUrl = e.target.value;
        setServiceUrl(newUrl);
        const errorMessage = validateUrl(newUrl);
        if (errorMessage == '') {
            setErrorInputs(false);
            setUrlError('');
        } else {
            setErrorInputs(true);
            setUrlError(errorMessage);
        }
    };

    const handleNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const newName = e.target.value;
        setName(newName);
        const errorMessage = validateName(newName);
        if (errorMessage == '') {
            setErrorInputs(false);
            setNameError('');
        } else {
            setErrorInputs(true);
            setNameError(errorMessage);
        }
    };

    const validateName = (name: string): string => {
        if (!name.trim()) {
            return '';
        }

        // Extract existing MCP toolkit names from the tools string
        const existingMcpToolkits = extractMcpToolkitNames(toolsStringList);
        
        // Check if the name already exists (case-insensitive comparison)
        const nameExists = existingMcpToolkits.some(
            existingName => existingName.toLowerCase() === name.trim().toLowerCase()
        );
        
        if (nameExists && !editMode) {
            return 'An MCP server with this name already exists';
        }
        
        // In edit mode, allow the current name but not other existing names
        if (nameExists && editMode && props.name && name.trim().toLowerCase() !== props.name.toLowerCase()) {
            return 'An MCP server with this name already exists';
        }
        
        return '';
    };

    const extractMcpToolkitNames = (toolsString: string): string[] => {
        const names: string[] = [];
        
        // Regex to match McpToolKit with name in info object
        const mcpToolkitPattern = /McpToolKit\([^}]*info\s*=\s*\{[^}]*name:\s*"([^"]+)"/g;
        let match;
        
        while ((match = mcpToolkitPattern.exec(toolsString)) !== null) {
            names.push(match[1]);
        }
        
        return names;
    };

    const handleSelectAllTools = () => {
        if (selectedMcpTools.size === mcpTools.length) {
            // Deselect all
            setSelectedMcpTools(new Set());
        } else {
            // Select all
            setSelectedMcpTools(new Set(mcpTools.map(tool => tool.name)));
        }
    };

    const handleOnSave = async () => {
        console.log(">>> save value", { selectedTool, selectedMcpTools: Array.from(selectedMcpTools) });
        
        // Use the same logic as the display to determine the name
        let finalName;
        if (name.trim() !== "") {
            finalName = name.trim();
        } else {
            finalName = mcpToolkitCount > 1 ? `MCP Server 0${mcpToolkitCount}` : "MCP Server";
        }
        
        const payload = {
            name: finalName,
            serviceUrl: serviceUrl.trim(),
            configs: configs,
            toolSelection,
            selectedTools: toolSelection === "Selected" ? Array.from(selectedMcpTools) : []
        };
        console.log(">>> Saving with payload:", payload);

        setSavingForm(true);
        try {
            await rpcClient.getAIAgentRpcClient().updateMCPToolKit({
                agentFlowNode: agentNode,
                serviceUrl: `"${payload.serviceUrl}"`,
                serverName: finalName,
                selectedTools: payload.selectedTools
            });
            // update the agent node
            // const updatedAgentNode = await addMcpServerToAgentNode(agentNode, payload);
            // // generate the source code
            // const agentResponse = await rpcClient
            //     .getBIDiagramRpcClient()
            //     .getSourceCode({ filePath: agentFilePath.current, flowNode: updatedAgentNode });
            // console.log(">>> response getSourceCode with template ", { agentResponse });

            // // Only increment count after successful save
            // setMcpToolkitCount(mcpToolkitCount + 1);
            // console.log(">>> toolkit count incremented to", mcpToolkitCount + 1);

            onSave?.();
        } catch (error) {
            console.error(">>> Error saving MCP server", error);
            // You might want to show an error message to the user here
        } finally {
            setSavingForm(false);
        }
    };

    const handleOnEdit = async () => {
        console.log(">>> edit value", { selectedTool, selectedMcpTools: Array.from(selectedMcpTools) });
        
        const payload = {
            name: name.trim(),
            serviceUrl: serviceUrl.trim(),
            configs: configs,
            toolSelection,
            selectedTools: toolSelection === "Selected" ? Array.from(selectedMcpTools) : []
        };
        
        console.log(">>> Updating with payload:", payload);

        setSavingForm(true);
        try {
            // Use the original name (from props) to identify which MCP server to update
            const originalToolName = props.name || "";
            
            // Update the existing MCP server configuration
            const updatedAgentNode = await updateMcpServerToAgentNode(agentNode, payload, originalToolName);
            
            if (updatedAgentNode) {
                // generate the source code
                const agentResponse = await rpcClient
                    .getBIDiagramRpcClient()
                    .getSourceCode({ filePath: agentFilePath.current, flowNode: updatedAgentNode });
                console.log(">>> response getSourceCode with template ", { agentResponse });

                onSave?.();
            } else {
                console.error(">>> Failed to update MCP server - updatedAgentNode is null");
            }
        } catch (error) {
            console.error(">>> Error updating MCP server", error);
            // You might want to show an error message to the user here
        } finally {
            setSavingForm(false);
        }
    };

    const hasExistingTools = existingTools.length > 0;
    const isToolSelected = selectedTool !== null;
    const canSave = serviceUrl.trim() && (toolSelection !== "Selected" || selectedMcpTools.size > 0);

    console.log(">>> rendering conditions", { hasExistingTools, isToolSelected, canSave, editMode });

    const renderToolsSelection = () => {
        if (toolSelection !== "Selected") {
            return null;
        }

        return (
            <ToolsContainer>
                <ToolsHeader>
                    <ToolsTitle>Available Tools</ToolsTitle>
                    {mcpTools.length > 0 && (
                        <Button
                            size="small"
                            onClick={handleSelectAllTools}
                            disabled={loadingMcpTools}
                        >
                            {selectedMcpTools.size === mcpTools.length ? "Deselect All" : "Select All"}
                        </Button>
                    )}
                </ToolsHeader>

                {loadingMcpTools && (
                    <LoadingMessage>
                        <RelativeLoader size="small" />
                        Loading tools from MCP server...
                    </LoadingMessage>
                )}

                {mcpToolsError && (
                    <ErrorMessage>{mcpToolsError}</ErrorMessage>
                )}

                {mcpTools.length > 0 && (
                    <ToolCheckboxContainer>
                        {mcpTools.map((tool) => (
                            <ToolCheckboxItem key={tool.name}>
                                <CheckBox
                                    label=""
                                    checked={selectedMcpTools.has(tool.name)}
                                    disabled={loadingMcpTools}
                                    onChange={() => !loadingMcpTools && handleToolSelectionChange(tool.name, !selectedMcpTools.has(tool.name))}
                                >
                                </CheckBox>
                                <div>
                                    <div style={{ fontWeight: 'bold' }}>{tool.name}</div>
                                    {tool.description && (
                                        <div style={{ fontSize: '12px', color: ThemeColors.ON_SURFACE_VARIANT }}>
                                            {tool.description}
                                        </div>
                                    )}
                                </div>
                            </ToolCheckboxItem>
                        ))}
                    </ToolCheckboxContainer>
                )}

                {!loadingMcpTools && !mcpToolsError && mcpTools.length === 0 && serviceUrl.trim() && (
                    <div style={{ color: ThemeColors.ON_SURFACE_VARIANT, fontSize: '12px' }}>
                        No tools available from this MCP server
                    </div>
                )}
            </ToolsContainer>
        );
    };
    console.log(">>> agentNode", agentCallNode);

    const DropdownContainer = styled.div`
    width: 100%;
`;

    return (
        <Container>
            
            {loading && (
                <LoaderContainer>
                    <RelativeLoader />
                </LoaderContainer>
            )}

            <>
                <Column>
                    <Description>
                        {editMode ? "Edit MCP server configuration." : "Add an MCP server to provide tools to the Agent."}
                    </Description>
                    
                    <NameContainer>
                        <TextField
                            sx={{ flexGrow: 1, marginTop: 15 }}
                            disabled={false}
                            errorMsg={urlError}
                            label="Service URL"
                            size={70}
                            onChange={handleServiceUrlChange}
                            placeholder="Enter MCP server URL"
                            value={serviceUrl}
                        />
                    </NameContainer>

                    {/* TODO: Enable configs field later - needs proper wiring for Record<string, string> type
                    <NameContainer>
                        <TextField
                            sx={{ flexGrow: 1, marginTop: 15 }}
                            disabled={false}
                            label="Configs"
                            size={70}
                            onChange={(e) => setConfigs(e.target.value)}
                            placeholder="Enter server configurations (optional)"
                            value={""}
                        />
                    </NameContainer>
                    */}

                    <NameContainer>
                        <TextField
                            sx={{ flexGrow: 1, marginTop: 15 }}
                            disabled={false}
                            label="Name"
                            size={70}
                            errorMsg={nameError}
                            onChange={handleNameChange}
                            placeholder="Enter name for the MCP Tool Kit"
                            value={name != "" ? name : mcpToolkitCount > 1 ? `MCP Server 0${mcpToolkitCount}` : "MCP Server"}
                        />
                    </NameContainer>

                    <NameContainer style={{ marginTop: 15 }}>
                        <DropdownContainer>
                            <Dropdown
                                id="tool-selection"
                                label="Tools to Include"
                                value={toolSelection}
                                items={[
                                    { id: "All", value: "All" },
                                    { id: "Selected", value: "Selected" },
                                ]}
                                onValueChange={(value) => setToolSelection(value)}
                            />
                        </DropdownContainer>
                    </NameContainer>
                    {renderToolsSelection()}
                </Column>
                <Footer>
                    {editMode ? (
                        // Edit mode: Show only Save button
                        <PrimaryButton 
                            onClick={handleOnEdit} 
                            disabled={savingForm || !canSave || loadingMcpTools || errorInputs}
                        >
                            {savingForm ? "Saving..." : "Save"}
                        </PrimaryButton>
                    ) : (
                        // Add mode: Show Back and Add to Agent buttons
                        <>
                            <Button onClick={handleBack}>
                                Back
                            </Button>
                            <PrimaryButton 
                                onClick={handleOnSave} 
                                disabled={savingForm || !canSave || loadingMcpTools || errorInputs}
                            >
                                {savingForm ? "Adding..." : "Add to Agent"}
                            </PrimaryButton>
                        </>
                    )}
                </Footer>
            </>
        </Container>
    );
}
