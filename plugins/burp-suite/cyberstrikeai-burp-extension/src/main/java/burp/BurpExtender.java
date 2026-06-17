package burp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private CyberStrikeAITab tab;
    private final CyberStrikeAIClient client = new CyberStrikeAIClient();
    private String lastInstruction = HttpMessageFormatter.defaultInstruction();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("CyberStrikeAI Extension");

        this.tab = new CyberStrikeAITab();
        callbacks.addSuiteTab(tab);

        callbacks.registerContextMenuFactory(this);

        callbacks.printOutput("CyberStrikeAI extension loaded.");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> items = new ArrayList<>();

        JMenuItem sendItem = new JMenuItem("Send to CyberStrikeAI (stream test)");
        sendItem.addActionListener(e -> {
            IHttpRequestResponse[] selected = invocation.getSelectedMessages();
            if (selected == null || selected.length == 0) {
                return;
            }
            sendMessage(selected[0]);
        });

        items.add(sendItem);
        return items;
    }

    private void sendMessage(IHttpRequestResponse msg) {
        if (msg == null) return;
        CyberStrikeAIClient.Config cfg = tab.currentConfig();
        String token = tab.getToken();
        if (token == null || token.trim().isEmpty()) {
            JOptionPane.showMessageDialog(tab.getUiComponent(),
                    "Please click Validate first to obtain a token.",
                    "CyberStrikeAI", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String instruction = showInstructionEditor(tab.getUiComponent(), lastInstruction);
        if (instruction == null) {
            return;
        }
        lastInstruction = instruction;

        String prompt = HttpMessageFormatter.toPrompt(helpers, msg, instruction);
        String title = HttpMessageFormatter.getRequestTitle(helpers, msg);
        String agentModeStr = cfg.agentMode.displayName;
        String runId = tab.startNewRun(title, agentModeStr, msg);
        tab.appendProgressToRun(runId, "\n[server] " + cfg.baseUrl + "\n\n");

        client.streamTest(cfg, token, prompt, new CyberStrikeAIClient.StreamListener() {
            @Override
            public void onEvent(String type, String message, String rawJson) {
                if (type == null) type = "";
                switch (type) {
                    case "response_start":
                        tab.appendProgressToRun(runId, "\n\n[主回复]\n");
                        break;
                    case "response_delta":
                        if (message != null && !message.isEmpty()) {
                            tab.appendFinalToRun(runId, message);
                        }
                        break;
                    case "response":
                        tab.appendFinalToRun(runId, message);
                        tab.setFinalResponse(runId, message);
                        break;
                    case "eino_agent_reply_stream_start":
                        tab.appendProgressToRun(runId, "\n\n[子代理回复]\n");
                        break;
                    case "eino_agent_reply_stream_delta":
                        if (message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, message);
                        }
                        break;
                    case "eino_agent_reply_stream_end":
                        tab.appendProgressToRun(runId, "\n");
                        break;
                    case "eino_agent_reply":
                        if (message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, "\n\n[子代理回复]\n" + message + "\n");
                        }
                        break;
                    case "progress":
                        tab.appendProgressToRun(runId, "\n[progress] " + message + "\n");
                        tab.setRunStatus(runId, "running");
                        break;
                    case "cancelled":
                        tab.appendProgressToRun(runId, "\n[cancelled] " + message + "\n");
                        tab.setRunStatus(runId, "cancelled");
                        break;
                    case "error":
                        tab.appendProgressToRun(runId, "\n[error] " + message + "\n");
                        tab.setRunStatus(runId, "error");
                        break;
                    case "reasoning_chain_stream_start":
                        tab.appendProgressToRun(runId, "\n\n[推理过程]\n");
                        break;
                    case "reasoning_chain_stream_delta":
                        if (message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, message);
                        }
                        break;
                    case "reasoning_chain_stream_end":
                        tab.appendProgressToRun(runId, "\n");
                        break;
                    case "reasoning_chain":
                        if (message != null && !message.isEmpty()) {
                            String streamId = rawJson != null ? SimpleJson.extractStringField(rawJson, "streamId") : "";
                            if (streamId == null || streamId.isEmpty()) {
                                tab.appendProgressToRun(runId, "\n\n[推理过程]\n" + message + "\n");
                            }
                        }
                        break;
                    case "thinking_stream_start":
                        if (tab.isShowDebugEvents()) {
                            tab.resetThinkingStream(runId);
                        }
                        break;
                    case "thinking_stream_delta":
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, message);
                        }
                        break;
                    case "tool_call":
                    case "tool_result":
                    case "tool_result_delta":
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, "\n[" + type + "] " + message + "\n");
                        }
                        break;
                    case "conversation":
                        if (rawJson != null) {
                            String convId = SimpleJson.extractStringField(rawJson, "conversationId");
                            if (convId != null && !convId.trim().isEmpty()) {
                                tab.setRunConversationId(runId, convId);
                            }
                        }
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()) {
                            tab.appendProgressToRun(runId, "\n[" + type + "] " + message + "\n");
                        }
                        break;
                    case "done":
                        break;
                    default:
                        if (tab.isShowDebugEvents() && message != null && !message.isEmpty()
                                && !type.endsWith("_stream_delta") && !type.endsWith("_stream_start")
                                && !type.endsWith("_stream_end")) {
                            tab.appendProgressToRun(runId, "\n[" + type + "] " + message + "\n");
                        }
                        break;
                }
            }

            @Override
            public void onError(String message, Exception e) {
                boolean cancelled = message != null && message.toLowerCase().contains("cancel");
                tab.appendProgressToRun(runId, cancelled ? "\n[info] " + message + "\n" : "\n[error] " + message + "\n");
                tab.setRunStatus(runId, cancelled ? "cancelled" : "error");
                callbacks.printError("CyberStrikeAI stream error: " + message);
                if (e != null) {
                    callbacks.printError(e.toString());
                }
            }

            @Override
            public void onDone() {
                tab.appendProgressToRun(runId, "\n\n[done]\n");
                tab.setRunStatus(runId, "done");
            }
        });
    }

    private static String showInstructionEditor(Component parent, String initialValue) {
        JTextArea editor = new JTextArea(
                initialValue == null || initialValue.trim().isEmpty()
                        ? HttpMessageFormatter.defaultInstruction()
                        : initialValue,
                6,
                70
        );
        editor.setLineWrap(true);
        editor.setWrapStyleWord(true);
        editor.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 13));

        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.add(new JLabel("Edit instruction before sending:"), BorderLayout.NORTH);
        panel.add(new JScrollPane(editor), BorderLayout.CENTER);

        int result = JOptionPane.showConfirmDialog(
                parent,
                panel,
                "Customize Prompt Instruction",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );
        if (result != JOptionPane.OK_OPTION) {
            return null;
        }
        String value = editor.getText();
        if (value == null || value.trim().isEmpty()) {
            return HttpMessageFormatter.defaultInstruction();
        }
        return value.trim();
    }
}

