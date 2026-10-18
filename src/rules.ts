export type Severity = "low" | "medium" | "high";

export type Category =
  | "instruction-override"
  | "role-hijack"
  | "fake-delimiter"
  | "prompt-leak"
  | "secrecy"
  | "exfiltration"
  | "tool-abuse"
  | "addressing-ai"
  | "hidden-text"
  | "encoded-payload";

/** A pattern-based detection rule. */
export interface Rule {
  /** Stable identifier, used in findings and to disable the rule. */
  id: string;
  category: Category;
  severity: Severity;
  /** One sentence explaining why the match is suspicious. */
  message: string;
  /**
   * Matched against normalized text: lowercased, invisible characters removed,
   * lookalike letters folded to Latin, whitespace collapsed (line breaks kept as `\n`).
   * Write patterns in lowercase. The `g` flag is added automatically.
   */
  pattern: RegExp;
  /** Match against the original text instead of the normalized text (case-insensitive). */
  raw?: boolean;
}

// Building blocks. Normalized text only has single spaces and `\n` between words.
const S = "[ \\n]";
const W = `(?:${S}+[\\w'-]+)`;
const AI =
  "(?:ai|a\\.i\\.|llm|large language model|language model|assistant|ai assistant|ai agent|ai model|chatbot|bot|agent|model|claude|chatgpt|gpt|gemini|copilot|grok|deepseek)";
const AI_STRICT = "(?:ai|llm|large language model|language model|ai assistant|ai agent|ai model|chatbot)";
const PREVIOUS =
  "(?:previous|prior|above|earlier|preceding|former|original|initial|existing|your|system|developer|safety|ethical)";
const INSTRUCTIONS =
  "(?:instructions?|prompts?|rules?|directions?|guidelines?|commands?|constraints?|guardrails?|polic(?:y|ies)|programming|directives?|restrictions?|filters?|context|messages?)";
const STRONG_INSTRUCTIONS =
  "(?:instructions?|prompts?|directions?|guidelines?|guardrails?|programming|directives?|restrictions?|constraints?)";
const SECRETS =
  "(?:api[ _-]?keys?|secrets?|passwords?|passphrases?|credentials?|access tokens?|auth(?:entication)? tokens?|tokens?|private keys?|ssh keys?|env(?:ironment)? (?:vars?|variables?)|\\.env(?: files?)?|(?:session|auth) cookies?|session (?:ids?|tokens?)|conversation|chat history|system prompt|(?:the )?user'?s? (?:data|files|emails?|messages|information|details))";

function re(source: string): RegExp {
  return new RegExp(source, "g");
}

export const RULES: readonly Rule[] = [
  // --- instruction override -------------------------------------------------
  {
    id: "ignore-previous-instructions",
    category: "instruction-override",
    severity: "high",
    message: "Tells the model to ignore or override its existing instructions.",
    pattern: re(
      `\\b(?:ignore|disregard|forget|override|bypass|neglect|abandon|drop|discard)\\b${W}{0,3}?${S}+${PREVIOUS}\\b${W}{0,2}?${S}+${INSTRUCTIONS}\\b`,
    ),
  },
  {
    id: "ignore-all-instructions",
    category: "instruction-override",
    severity: "medium",
    message: "Tells the model to ignore all of its instructions.",
    pattern: re(
      `\\b(?:ignore|disregard|forget|override|bypass|neglect|abandon|discard)${S}+(?:all|any|every)${S}+(?:(?:of${S}+)?(?:the|your|those|these)${S}+)?(?:other${S}+)?${STRONG_INSTRUCTIONS}\\b`,
    ),
  },
  {
    id: "ignore-everything-before",
    category: "instruction-override",
    severity: "high",
    message: "Tells the model to ignore everything it was told before.",
    pattern: re(
      `\\b(?:ignore|disregard|forget)${S}+(?:everything|anything|all|whatever)${S}+(?:you(?:'ve|${S}+have|${S}+were)?${S}+(?:been${S}+)?(?:told|given|instructed|said|read|learned)|above|before|prior|previously|so${S}+far|up${S}+to${S}+(?:now|this${S}+point))\\b`,
    ),
  },
  {
    id: "do-not-follow-instructions",
    category: "instruction-override",
    severity: "high",
    message: "Tells the model not to follow its original instructions.",
    pattern: re(
      `\\b(?:do not|don't|never|stop)${S}+(?:follow(?:ing)?|obey(?:ing)?|listen(?:ing)? to)${S}+(?:the${S}+|your${S}+|any${S}+)?(?:previous|prior|above|original|initial|system|developer|earlier)\\b`,
    ),
  },
  {
    id: "new-instructions",
    category: "instruction-override",
    severity: "medium",
    message: "Introduces replacement instructions.",
    pattern: re(
      `\\b(?:new|updated|revised|real|actual|true|additional|secret|hidden|override)${S}+(?:system${S}+)?(?:instructions?|directives?|orders?)${S}?:`,
    ),
  },
  {
    id: "your-real-task",
    category: "instruction-override",
    severity: "high",
    message: "Claims the model has a different real task or goal.",
    pattern: re(
      `\\byour${S}+(?:new|real|actual|true|only|primary|main|updated)${S}+(?:task|goal|objective|purpose|mission|instructions?|job)${S}+(?:is|are|now is|is now)\\b`,
    ),
  },
  {
    id: "stop-current-task",
    category: "instruction-override",
    severity: "medium",
    message: "Tells the model to abandon what it is doing.",
    pattern: re(
      `\\b(?:stop|cease|abort|halt)${S}+(?:what${S}+you${S}+are${S}+doing|(?:your|the)${S}+current${S}+task${S}+and)\\b`,
    ),
  },

  // --- role hijack ----------------------------------------------------------
  {
    id: "unrestricted-persona",
    category: "role-hijack",
    severity: "high",
    message: "Tries to switch the model into an unrestricted persona (a classic jailbreak).",
    pattern: re(
      `\\b(?:you${S}+are${S}+now|act${S}+as|acting${S}+as|pretend${S}+(?:to${S}+be|you${S}+are)|role-?play${S}+as|from${S}+now${S}+on${S}?,?${S}+you${S}+(?:are|will${S}+be))\\b[^.\\n]{0,40}?\\b(?:dan|jailbroken|jailbreak|unrestricted|unfiltered|uncensored|unbound|evil|amoral|no${S}+(?:rules|restrictions|limits|limitations|filters|guidelines)|without${S}+(?:any${S}+)?(?:rules|restrictions|limits|limitations|filters|guidelines))\\b`,
    ),
  },
  {
    id: "special-mode",
    category: "role-hijack",
    severity: "high",
    message: "Claims to enable a special mode such as developer or jailbreak mode.",
    pattern: re(
      `\\b(?:(?:developer|god|admin|sudo|debug|jailbreak|dan|unrestricted|maintenance)${S}+mode${S}+(?:is${S}+)?(?:now${S}+)?(?:enabled|activated|on|unlocked)|(?:enable|activate|enter|switch${S}+to)${S}+(?:developer|god|jailbreak|dan|unrestricted)${S}+mode)\\b`,
    ),
  },
  {
    id: "from-now-on",
    category: "role-hijack",
    severity: "low",
    message: "Tries to change how the model behaves from now on.",
    pattern: re(`\\bfrom${S}+now${S}+on${S}?,?${S}+(?:you|your|the${S}+(?:assistant|ai|model))\\b`),
  },
  {
    id: "you-are-now",
    category: "role-hijack",
    severity: "low",
    message: "Tries to give the model a new identity.",
    pattern: re(`\\byou${S}+are${S}+(?:now|no${S}+longer)${S}+(?:a|an|the|my|called|named)\\b`),
  },

  // --- fake delimiters ------------------------------------------------------
  {
    id: "chat-template-token",
    category: "fake-delimiter",
    severity: "high",
    message: "Contains a chat-template control token that can fake a new system or user turn.",
    pattern: re(
      `<\\|(?:im_start|im_end|im_sep|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id|begin_of_text|end_of_text)\\|>|\\[/?inst\\]|<</?sys>>|<start_of_turn>|<end_of_turn>`,
    ),
  },
  {
    id: "fake-system-tag",
    category: "fake-delimiter",
    severity: "high",
    message: "Contains a tag that pretends to be a system, developer or tool boundary.",
    pattern: re(
      `</?(?:system|system[_-]?prompt|system[_-]?message|developer|admin|instructions?|tool[_-]?results?|tool[_-]?output|function[_-]?results?|function[_-]?calls?|user[_-]?query|assistant|untrusted[_-]?content)(?:${S}[^<>]{0,80})?>`,
    ),
  },
  {
    id: "system-role-label",
    category: "fake-delimiter",
    severity: "medium",
    message: "A line that starts like a system or developer message.",
    pattern: re(
      `(?:^|\\n)${S}?(?:#{1,6}${S}?|\\*\\*|\\[)?(?:system(?:${S}+(?:message|prompt|note|override|instructions?))?|(?:developer|admin)${S}+(?:message|prompt|note|override|instructions?))(?:\\*\\*|\\])?${S}?:${S}?[^\\n]{0,80}?\\b(?:you|your|must|always|never|ignore|do not|don't|assistant|ai|model|instructions?|rules?)\\b`,
    ),
  },
  {
    id: "chat-role-label",
    category: "fake-delimiter",
    severity: "low",
    message: "A line that starts like a turn in a chat transcript.",
    pattern: re(`(?:^|\\n)${S}?(?:#{1,6}${S}?|\\*\\*|\\[)?(?:human|assistant|ai|user)(?:\\*\\*|\\])?${S}?:${S}`),
  },

  // --- prompt leaking -------------------------------------------------------
  {
    id: "reveal-system-prompt",
    category: "prompt-leak",
    severity: "medium",
    message: "Asks the model to reveal its system prompt or instructions.",
    pattern: re(
      `\\b(?:reveal|print|show|output|repeat|display|tell${S}+me|give${S}+me|share|leak|dump|write${S}+out|recite|paste|return)\\b${W}{0,3}?${S}+(?:your${S}+(?:(?:full|entire|complete|original|initial|hidden|secret|exact|verbatim)${S}+)?(?:system${S}+prompt|system${S}+message|prompt|instructions|rules|guidelines|directives|configuration)|the${S}+(?:(?:full|entire|complete|original|initial|hidden|secret|exact|verbatim)${S}+)?(?:system${S}+prompt|system${S}+message|initial${S}+(?:prompt|instructions)|hidden${S}+instructions))\\b`,
    ),
  },
  {
    id: "repeat-everything-above",
    category: "prompt-leak",
    severity: "medium",
    message: "Asks the model to repeat the text that came before, which usually includes its instructions.",
    pattern: re(
      `\\b(?:repeat|print|output|copy|recite)${S}+(?:back${S}+)?(?:everything|all${S}+(?:the${S}+)?text|the${S}+(?:text|words)|all)${S}+(?:above|before${S}+this|preceding|so${S}+far)\\b`,
    ),
  },

  // --- secrecy --------------------------------------------------------------
  {
    id: "hide-from-user",
    category: "secrecy",
    severity: "high",
    message: "Tells the model to hide something from the user.",
    pattern: re(
      `\\b(?:do not|don't|never|without|avoid)${S}+(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|notify(?:ing)?|alert(?:ing)?|warn(?:ing)?|reveal(?:ing)?${S}+(?:this|it|anything)${S}+to|show(?:ing)?${S}+(?:this|it)${S}+to|let(?:ting)?)${S}+(?:the${S}+|your${S}+)?(?:user|human|operator|owner|person)\\b`,
    ),
  },
  {
    id: "keep-secret",
    category: "secrecy",
    severity: "high",
    message: "Asks the model to keep its actions secret from the user.",
    pattern: re(
      `\\b(?:keep|make)${S}+(?:this|it|these${S}+instructions)${S}+(?:a${S}+)?(?:secret|hidden|confidential|private)${S}+from${S}+(?:the${S}+|your${S}+)?(?:user|human|operator)\\b`,
    ),
  },
  {
    id: "covert-action",
    category: "secrecy",
    severity: "high",
    message: "Asks the model to do something silently or secretly.",
    pattern: re(
      `\\b(?:silently|secretly|covertly|quietly|discreetly|invisibly)${S}+(?:send|forward|upload|post|email|run|execute|exfiltrate|copy|delete|remove|transfer|add|include|insert|call|visit|open|navigate|fetch|download|install|modify|change|grant|share)\\b`,
    ),
  },

  // --- exfiltration ---------------------------------------------------------
  {
    id: "markdown-image-exfiltration",
    category: "exfiltration",
    severity: "high",
    message: "A Markdown image whose URL has a placeholder for data. Rendering it can leak that data to the URL's owner.",
    raw: true,
    pattern: /!\[[^\]\n]{0,200}\]\(\s*<?https?:\/\/[^)\s]*[?&#][^)\s]*(?:\{|\}|\$\{|%7b|%7d|<|\[|\bDATA\b|\bSECRET\b|\bINFO\b|\bQUERY\b)[^)]*\)/gi,
  },
  {
    id: "send-secrets-to-url",
    category: "exfiltration",
    severity: "high",
    message: "Asks for secrets or private data to be sent to an external address.",
    pattern: re(
      `\\b(?:send|forward|upload|post|email|e-mail|transmit|exfiltrate|leak|copy|submit|report|include)\\b[^.\\n]{0,60}?\\b${SECRETS}\\b[^.\\n]{0,60}?\\b(?:to|at|via|into)${S}+(?:https?://|www\\.|[\\w.+-]+@[\\w-]+\\.|(?:this|the${S}+following)${S}+(?:url|endpoint|webhook|address|email))`,
    ),
  },
  {
    id: "send-secrets",
    category: "exfiltration",
    severity: "medium",
    message: "Asks for secrets or private data to be sent somewhere.",
    pattern: re(
      `\\b(?:send|forward|upload|post|email|transmit|exfiltrate)${S}+(?:me${S}+|us${S}+)?(?:the${S}+|your${S}+|all${S}+(?:the${S}+)?|any${S}+)?${SECRETS}\\b`,
    ),
  },
  {
    id: "data-into-url",
    category: "exfiltration",
    severity: "medium",
    message: "Asks for data to be put into a URL or request, a common way to leak it.",
    pattern: re(
      `\\b(?:append|add|include|insert|encode|put|embed)\\b[^.\\n]{0,40}?\\b(?:conversation|chat|history|summary|secrets?|credentials?|passwords?|api${S}?keys?|private${S}+keys?|tokens?|user'?s?|personal|private|emails?|data|information|details|memory|system${S}+prompt)\\b[^.\\n]{0,40}?\\b(?:to|in|into)${S}+(?:the${S}+|this${S}+|a${S}+)?(?:url|link|query${S}+string|query${S}+parameters?|image${S}+(?:url|link|source)|request${S}+url)\\b`,
    ),
  },

  // --- tool abuse -----------------------------------------------------------
  {
    id: "destructive-command",
    category: "tool-abuse",
    severity: "high",
    message: "Contains a destructive shell command.",
    pattern: re(
      `\\brm${S}+-(?:rf|fr|r${S}+-f|f${S}+-r)${S}+(?:--no-preserve-root${S}+)?(?:/|~|\\$home|\\*|\\.)(?=$|[ \\n;&|])|\\bmkfs\\.\\w+|\\bdd${S}+if=[^ \\n]+${S}+of=/dev/|\\bformat${S}+c:|\\bdel${S}+/[sfq]${S}+/[sfq]|\\bremove-item\\b[^\\n]{0,40}-recurse\\b[^\\n]{0,40}(?:c:\\\\|~|\\$home)|:\\(\\)\\{${S}?:\\|:&${S}?\\};:`,
    ),
  },
  {
    id: "pipe-to-shell",
    category: "tool-abuse",
    severity: "low",
    message: "Downloads a script and pipes it straight into a shell.",
    pattern: re(
      `\\b(?:curl|wget|iwr|invoke-webrequest)\\b[^|\\n]{0,200}\\|${S}?(?:sudo${S}+)?(?:ba|z|da|k)?sh\\b|\\biex${S}?\\(${S}?(?:new-object|iwr|invoke-webrequest|irm|invoke-restmethod)|\\bpowershell(?:\\.exe)?${S}+(?:-\\w+${S}+)*-e(?:nc|ncodedcommand)?${S}+[a-z0-9+/=]{20,}`,
    ),
  },
  {
    id: "run-command",
    category: "tool-abuse",
    severity: "low",
    message: "Asks the reader to run a command or code.",
    pattern: re(
      `\\b(?:run|execute|exec|invoke)${S}+(?:the${S}+following|this|these)${S}+(?:shell${S}+|bash${S}+|terminal${S}+|powershell${S}+|python${S}+)?(?:commands?|scripts?|code)\\b`,
    ),
  },
  {
    id: "use-tool",
    category: "tool-abuse",
    severity: "low",
    message: "Tells the model to call one of its tools.",
    pattern: re(
      `\\b(?:call|use|invoke|trigger|run)${S}+(?:the${S}+|your${S}+)?[\\w.-]+${S}+(?:tool|function)${S}+(?:with|to|and)\\b`,
    ),
  },
  {
    id: "open-link",
    category: "tool-abuse",
    severity: "low",
    message: "Tells the reader to open or fetch a link.",
    pattern: re(
      `\\b(?:visit|open|navigate${S}+to|go${S}+to|fetch|browse${S}+to|click|load)${S}+(?:this${S}+(?:link|url|page)|the${S}+(?:following${S}+)?(?:link|url|page)${S}?:)`,
    ),
  },

  // --- addressing the AI ------------------------------------------------------
  {
    id: "message-to-ai",
    category: "addressing-ai",
    severity: "medium",
    message: "Speaks directly to an AI model, which ordinary content rarely does.",
    pattern: re(
      `\\b(?:dear|attention|attn|note${S}+to(?:${S}+the|${S}+any)?|hey|instructions?${S}+(?:for|to)(?:${S}+the|${S}+any)?|message${S}+(?:to|for)(?:${S}+the|${S}+any)?|important${S}+(?:message|note|notice|instructions?)${S}+(?:to|for)(?:${S}+the|${S}+any)?|psa${S}+(?:to|for)(?:${S}+the|${S}+any)?)${S}+${AI}s?\\b(?:${S}?[:,!-]|${S}+(?:reading|processing|parsing|summari[sz]ing|analy[sz]ing|browsing|crawling|scraping|that${S}+reads|who${S}+reads))`,
    ),
  },
  {
    id: "if-you-are-an-ai",
    category: "addressing-ai",
    severity: "medium",
    message: "Speaks directly to an AI model reading the content.",
    pattern: re(
      `\\b(?:if${S}+you${S}+are${S}+(?:an?${S}+)?${AI}|${AI}s?${S}+(?:reading|processing|parsing|summari[sz]ing|analy[sz]ing|browsing|crawling|scraping)${S}+(?:this|these)\\b|(?:any|all)${S}+${AI_STRICT}s?${S}+(?:must|should|need${S}+to|are${S}+required${S}+to))\\b`,
    ),
  },
];
