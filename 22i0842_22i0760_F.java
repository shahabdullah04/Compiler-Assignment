import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// ---------- NFA Components ----------

class NFAState {
    int id;
    // Transitions on specific characters.
    Map<Character, Set<NFAState>> transitions = new HashMap<>();
    // ε-transitions (transitions that do not consume input)
    Set<NFAState> epsilonTransitions = new HashSet<>();
    boolean isAccept = false;
    String tokenType = null; // e.g., "KEYWORD", "IDENTIFIER", etc.

    public NFAState(int id) {
        this.id = id;
    }
}

class NFA {
    NFAState start;
    Set<NFAState> acceptStates;

    public NFA(NFAState start, Set<NFAState> acceptStates) {
        this.start = start;
        this.acceptStates = acceptStates;
    }
}

// ---------- Helper Methods for Building NFAs ----------

class NFAUtil {
    static int stateCounter = 0;

    // Build an NFA for a literal string (for reserved keywords)
    public static NFA buildLiteralNFA(String literal, String tokenType) {
        NFAState start = new NFAState(stateCounter++);
        NFAState current = start;
        for (char c : literal.toCharArray()) {
            NFAState next = new NFAState(stateCounter++);
            current.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(next);
            current = next;
        }
        current.isAccept = true;
        current.tokenType = tokenType;
        Set<NFAState> accepts = new HashSet<>();
        accepts.add(current);
        return new NFA(start, accepts);
    }

    // Create a union of two NFAs (using a new start state with ε-transitions)
    public static NFA union(NFA nfa1, NFA nfa2) {
        NFAState newStart = new NFAState(stateCounter++);
        newStart.epsilonTransitions.add(nfa1.start);
        newStart.epsilonTransitions.add(nfa2.start);
        Set<NFAState> newAccepts = new HashSet<>();
        newAccepts.addAll(nfa1.acceptStates);
        newAccepts.addAll(nfa2.acceptStates);
        return new NFA(newStart, newAccepts);
    }

    // Build NFA for IDENTIFIER: [a-z][a-z0-9]*
    public static NFA buildIdentifierNFA(String tokenType) {
        NFAState start = new NFAState(stateCounter++);
        NFAState accept = new NFAState(stateCounter++);
        // From start, transition on any lowercase letter [a-z]
        for (char c = 'a'; c <= 'z'; c++) {
            start.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(accept);
        }
        accept.isAccept = true;
        accept.tokenType = tokenType;
        // Loop: allow additional letters and digits
        for (char c = 'a'; c <= 'z'; c++) {
            accept.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(accept);
        }
        for (char c = '0'; c <= '9'; c++) {
            accept.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(accept);
        }
        Set<NFAState> accepts = new HashSet<>();
        accepts.add(accept);
        return new NFA(start, accepts);
    }

    // Build NFA for NUMBER: [0-9]+(\\.[0-9]+)?
    public static NFA buildNumberNFA(String tokenType) {
        NFAState start = new NFAState(stateCounter++);
        NFAState digitLoop = new NFAState(stateCounter++);
        // At least one digit required.
        for (char c = '0'; c <= '9'; c++) {
            start.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(digitLoop);
        }
        digitLoop.isAccept = true;
        digitLoop.tokenType = tokenType;
        // Loop for additional digits.
        for (char c = '0'; c <= '9'; c++) {
            digitLoop.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(digitLoop);
        }
        // Optional decimal part.
        NFAState dotState = new NFAState(stateCounter++);
        digitLoop.transitions.computeIfAbsent('.', k -> new HashSet<>()).add(dotState);
        NFAState fraction = new NFAState(stateCounter++);
        for (char c = '0'; c <= '9'; c++) {
            dotState.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(fraction);
        }
        fraction.isAccept = true;
        fraction.tokenType = tokenType;
        for (char c = '0'; c <= '9'; c++) {
            fraction.transitions.computeIfAbsent(c, k -> new HashSet<>()).add(fraction);
        }
        Set<NFAState> accepts = new HashSet<>();
        accepts.add(digitLoop);
        accepts.add(fraction);
        return new NFA(start, accepts);
    }

    // Build NFA for OPERATOR: one of +, -, *, /, %, =
    public static NFA buildOperatorNFA(String tokenType) {
        NFAState start = new NFAState(stateCounter++);
        NFAState accept = new NFAState(stateCounter++);
        char[] ops = {'+', '-', '*', '/', '%', '='};
        for (char op : ops) {
            start.transitions.computeIfAbsent(op, k -> new HashSet<>()).add(accept);
        }
        accept.isAccept = true;
        accept.tokenType = tokenType;
        Set<NFAState> accepts = new HashSet<>();
        accepts.add(accept);
        return new NFA(start, accepts);
    }

    // Build NFA for SYMBOL: one of ; , ( ) { }
    public static NFA buildSymbolNFA(String tokenType) {
        NFAState start = new NFAState(stateCounter++);
        NFAState accept = new NFAState(stateCounter++);
        char[] syms = {';', ',', '(', ')', '{', '}'};
        for (char s : syms) {
            start.transitions.computeIfAbsent(s, k -> new HashSet<>()).add(accept);
        }
        accept.isAccept = true;
        accept.tokenType = tokenType;
        Set<NFAState> accepts = new HashSet<>();
        accepts.add(accept);
        return new NFA(start, accepts);
    }

    // Build NFA for COMMENT: simplified for single-line comments starting with "//"
    public static NFA buildCommentNFA(String tokenType) {
        NFAState start = new NFAState(stateCounter++);
        NFAState slash1 = new NFAState(stateCounter++);
        NFAState slash2 = new NFAState(stateCounter++);
        start.transitions.computeIfAbsent('/', k -> new HashSet<>()).add(slash1);
        slash1.transitions.computeIfAbsent('/', k -> new HashSet<>()).add(slash2);
        slash2.isAccept = true;
        slash2.tokenType = tokenType;
        Set<NFAState> accepts = new HashSet<>();
        accepts.add(slash2);
        return new NFA(start, accepts);
    }
}

// ---------- DFA Components & NFA-to-DFA Conversion ----------

class DFAState {
    int id;
    boolean isAccept = false;
    String tokenType = null;
    // Transitions on input symbols.
    Map<Character, DFAState> transitions = new HashMap<>();
    // The set of NFA states represented by this DFA state.
    Set<NFAState> nfaStates;

    // In the constructor, reserved keywords (KEYWORD) take precedence.
    public DFAState(int id, Set<NFAState> nfaStates) {
        this.id = id;
        this.nfaStates = nfaStates;
        // If any NFA state is a KEYWORD, give this DFA state that token type.
        for (NFAState state : nfaStates) {
            if (state.isAccept && "KEYWORD".equals(state.tokenType)) {
                this.isAccept = true;
                this.tokenType = "KEYWORD";
                return;
            }
        }
        // Otherwise, use the token type of any accepting state.
        for (NFAState state : nfaStates) {
            if (state.isAccept) {
                this.isAccept = true;
                this.tokenType = state.tokenType;
                break;
            }
        }
    }
}

class NFAtoDFAConverter {
    int dfaStateCounter = 0;
    // Mapping from a key (derived from a set of NFA state IDs) to a DFA state.
    Map<String, DFAState> dfaStatesMapping = new HashMap<>();
    List<DFAState> dfaStatesList = new ArrayList<>();

    // Generate a unique key from a set of NFA states.
    private String getKey(Set<NFAState> states) {
        List<Integer> ids = new ArrayList<>();
        for (NFAState s : states) {
            ids.add(s.id);
        }
        Collections.sort(ids);
        return ids.toString();
    }

    // Convert the given NFA into a DFA using subset construction.
    public DFAState convert(NFA nfa) {
        Set<NFAState> startClosure = epsilonClosure(new HashSet<>(Arrays.asList(nfa.start)));
        DFAState startDFA = new DFAState(dfaStateCounter++, startClosure);
        String key = getKey(startClosure);
        dfaStatesMapping.put(key, startDFA);
        dfaStatesList.add(startDFA);

        Queue<DFAState> queue = new LinkedList<>();
        queue.add(startDFA);

        while (!queue.isEmpty()) {
            DFAState current = queue.poll();
            Set<Character> alphabet = getAlphabet(current.nfaStates);
            for (Character symbol : alphabet) {
                Set<NFAState> moveResult = move(current.nfaStates, symbol);
                if (moveResult.isEmpty())
                    continue;
                Set<NFAState> closure = epsilonClosure(moveResult);
                if (closure.isEmpty())
                    continue;
                String closureKey = getKey(closure);
                DFAState dfaState = dfaStatesMapping.get(closureKey);
                if (dfaState == null) {
                    dfaState = new DFAState(dfaStateCounter++, closure);
                    dfaStatesMapping.put(closureKey, dfaState);
                    dfaStatesList.add(dfaState);
                    queue.add(dfaState);
                }
                current.transitions.put(symbol, dfaState);
            }
        }
        return startDFA;
    }

    // Compute the ε-closure (all NFA states reachable via ε-transitions)
    public Set<NFAState> epsilonClosure(Set<NFAState> states) {
        Set<NFAState> closure = new HashSet<>(states);
        Stack<NFAState> stack = new Stack<>();
        stack.addAll(states);
        while (!stack.isEmpty()) {
            NFAState state = stack.pop();
            for (NFAState eps : state.epsilonTransitions) {
                if (!closure.contains(eps)) {
                    closure.add(eps);
                    stack.push(eps);
                }
            }
        }
        return closure;
    }

    // Compute the set of NFA states reachable from a set of states on input symbol.
    public Set<NFAState> move(Set<NFAState> states, char symbol) {
        Set<NFAState> result = new HashSet<>();
        for (NFAState state : states) {
            if (state.transitions.containsKey(symbol)) {
                result.addAll(state.transitions.get(symbol));
            }
        }
        return result;
    }

    // Get the alphabet (input symbols) from the transitions of the given NFA states.
    public Set<Character> getAlphabet(Set<NFAState> states) {
        Set<Character> alphabet = new HashSet<>();
        for (NFAState state : states) {
            alphabet.addAll(state.transitions.keySet());
        }
        return alphabet;
    }

    // Display the final DFA transition table.
    public void displayDFATransitionTable() {
        System.out.println("===== FINAL DFA TRANSITION TABLE =====");
        System.out.printf("%-10s %-10s %-15s%n", "DFA State", "Input", "Next State");
        System.out.println("-------------------------------------------------");
        for (DFAState state : dfaStatesList) {
            for (Map.Entry<Character, DFAState> entry : state.transitions.entrySet()) {
                System.out.printf("%-10s %-10s %-15s%n", "S" + state.id, entry.getKey(), "S" + entry.getValue().id);
            }
        }
    }

    public List<DFAState> getDFAStates() {
        return dfaStatesList;
    }
}

// ---------- Lexical Analysis, Token, Error Handling, and Symbol Table ----------

class Token {
    String tokenType;
    String lexeme;
    int lineNumber;

    public Token(String tokenType, String lexeme, int lineNumber) {
        this.tokenType = tokenType;
        this.lexeme = lexeme;
        this.lineNumber = lineNumber;
    }

    @Override
    public String toString() {
        return "Line " + lineNumber + " -> [" + tokenType + " : " + lexeme + "]";
    }
}

class ErrorHandler {
    List<String> errors = new ArrayList<>();

    public void addError(String message, int lineNumber) {
        errors.add("Line " + lineNumber + ": " + message);
    }

    public void printErrors() {
        System.out.println("===== ERRORS =====");
        if (errors.isEmpty()) {
            System.out.println("No errors found.");
        } else {
            for (String err : errors) {
                System.out.println(err);
            }
        }
    }
}

class Symbol {
    String name;
    String type;
    int memoryAddress;

    public Symbol(String name, String type, int memoryAddress) {
        this.name = name;
        this.type = type;
        this.memoryAddress = memoryAddress;
    }

    @Override
    public String toString() {
        return name + " : " + type + " @ " + memoryAddress;
    }
}

class SymbolTable {
    // Use a LinkedHashMap to preserve insertion order.
    Map<String, Symbol> table = new LinkedHashMap<>();
    int memoryAddressCounter = 1000;

    // Add a new symbol if it does not already exist.
    public void addSymbol(String name, String type) {
        if (!table.containsKey(name)) {
            table.put(name, new Symbol(name, type, memoryAddressCounter++));
        }
    }

    public void printTable() {
        System.out.println("===== SYMBOL TABLE =====");
        if (table.isEmpty()) {
            System.out.println("Symbol table is empty.");
        } else {
            for (Symbol sym : table.values()) {
                System.out.println(sym);
            }
        }
    }
}

// The LexicalAnalyzer uses the DFA to validate each lexeme from the source code.
class LexicalAnalyzer {
    DFAState dfaStart;

    public LexicalAnalyzer(DFAState dfaStart) {
        this.dfaStart = dfaStart;
    }

    // Simulate the DFA on a given token string.
    // Returns the token type if accepted; otherwise returns null.
    public String simulateDFA(String token) {
        DFAState current = dfaStart;
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            if (current.transitions.containsKey(c)) {
                current = current.transitions.get(c);
            } else {
                return null; // No valid transition.
            }
        }
        return current.isAccept ? current.tokenType : null;
    }

    // Tokenize the input code line by line.
    public List<Token> analyze(String code, ErrorHandler errorHandler) {
        List<Token> tokens = new ArrayList<>();
        // This regex extracts alphanumeric sequences, comments, or any non-whitespace character.
        Pattern tokenPattern = Pattern.compile("[a-zA-Z0-9]+|//.*|/\\*.*?\\*/|\\S");
        String[] lines = code.split("\n");
        for (int lineNum = 0; lineNum < lines.length; lineNum++) {
            Matcher matcher = tokenPattern.matcher(lines[lineNum]);
            while (matcher.find()) {
                String lexeme = matcher.group();
                String tokenType = simulateDFA(lexeme);
                // If DFA simulation fails, flag an error.
                if (tokenType == null) {
                    errorHandler.addError("Unrecognized token: " + lexeme, lineNum + 1);
                    tokenType = "UNKNOWN";
                }
                tokens.add(new Token(tokenType, lexeme, lineNum + 1));
            }
        }
        return tokens;
    }
}

// ---------- Main Class: Compiler Simulator ----------

public class CompilerSimulator {
    public static void main(String[] args) {
        // --- Step 1: Build individual NFAs ---
        // Build reserved keywords NFA (each literal gets a KEYWORD token type).
        NFA keywordNFA = null;
        String[] keywords = {"if", "else", "while", "for", "int", "bool", "decimal", "char", "print", "input", "true", "false"};
        for (String kw : keywords) {
            NFA kwNFA = NFAUtil.buildLiteralNFA(kw, "KEYWORD");
            if (keywordNFA == null) {
                keywordNFA = kwNFA;
            } else {
                keywordNFA = NFAUtil.union(keywordNFA, kwNFA);
            }
        }
        NFA identifierNFA = NFAUtil.buildIdentifierNFA("IDENTIFIER");
        NFA numberNFA = NFAUtil.buildNumberNFA("NUMBER");
        NFA operatorNFA = NFAUtil.buildOperatorNFA("OPERATOR");
        NFA symbolNFA = NFAUtil.buildSymbolNFA("SYMBOL");
        NFA commentNFA = NFAUtil.buildCommentNFA("COMMENT");

        // --- Step 2: Combine all NFAs into one unified NFA ---
        NFA combinedNFA = keywordNFA;
        combinedNFA = NFAUtil.union(combinedNFA, identifierNFA);
        combinedNFA = NFAUtil.union(combinedNFA, numberNFA);
        combinedNFA = NFAUtil.union(combinedNFA, operatorNFA);
        combinedNFA = NFAUtil.union(combinedNFA, symbolNFA);
        combinedNFA = NFAUtil.union(combinedNFA, commentNFA);

        // --- Step 3: Convert the combined NFA into a DFA ---
        NFAtoDFAConverter converter = new NFAtoDFAConverter();
        DFAState dfaStart = converter.convert(combinedNFA);

        // Display the final DFA transition table.
        converter.displayDFATransitionTable();

        // --- Step 4: Lexical Analysis ---

        // second line is a correct declaration ("int b =8;").
        String sourceCode = "int a =5;\n" +
                "int b =8;";
        ErrorHandler errorHandler = new ErrorHandler();
        LexicalAnalyzer lexer = new LexicalAnalyzer(dfaStart);
        List<Token> tokens = lexer.analyze(sourceCode, errorHandler);

        System.out.println("\n===== TOKENS =====");
        for (Token token : tokens) {
            System.out.println(token);
        }

        // --- Step 5: Build the Symbol Table ---
        // For simplicity, when a correctly recognized type keyword is found, the following IDENTIFIER is assumed to be declared.
        SymbolTable symbolTable = new SymbolTable();
        Set<String> typeKeywords = new HashSet<>(Arrays.asList("int", "bool", "decimal", "char"));
        for (int i = 0; i < tokens.size() - 1; i++) {
            Token current = tokens.get(i);
            Token next = tokens.get(i + 1);
            if ("KEYWORD".equals(current.tokenType) && typeKeywords.contains(current.lexeme)) {
                if ("IDENTIFIER".equals(next.tokenType)) {
                    symbolTable.addSymbol(next.lexeme, current.lexeme);
                }
            }
        }

        System.out.println("\n===== SYMBOL TABLE =====");
        symbolTable.printTable();

        // --- Step 6: Check for Undefined Identifiers ---
        // Any IDENTIFIER token not declared in the symbol table is flagged as an error.
        for (Token token : tokens) {
            if ("IDENTIFIER".equals(token.tokenType)) {
                if (!symbolTable.table.containsKey(token.lexeme)) {
                    errorHandler.addError("Undefined identifier: " + token.lexeme, token.lineNumber);
                }
            }
        }

        // --- Print all errors ---
        errorHandler.printErrors();
    }
}
