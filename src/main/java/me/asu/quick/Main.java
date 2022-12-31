package me.asu.quick;

import static me.asu.quick.ErrorCode.*;
import static me.asu.quick.util.StringUtils.dup;
import static me.asu.quick.util.StringUtils.isEmpty;


import java.util.Map;
import java.util.TreeMap;
import me.asu.quick.util.GetOpt;

public class Main {

    static Map<String, Command> commandMap = new TreeMap<>();

    static {
        Command[] list = new Command[]{
                new FileEncryptCmd(),
                new FileShowMetaInfoCmd(),
                new FileDecryptCmd(),
        };
        for (Command cmd : list) {
            commandMap.put(cmd.name(), cmd);
        }
    }

    public static void main(String[] args) throws Exception {
        // 使用 AES 算法的加密
        String cmd = null;
        if (args == null || args.length == 0 ) {
            showUsage(cmd);
            System.exit(PARAM_ERROR);
        } else if ("help".equalsIgnoreCase(args[0])) {
            if (args.length > 1) {
                cmd = args[1];
            }
            showUsage(cmd);
            System.exit(PARAM_ERROR);
        }
        Command command = commandMap.get(args[0]);
        if (command == null) {
            System.out.println("Not support this command: " + command);
            System.exit(COM_NOT_SUPPORT_ERROR);
        }
        String[] subArgs = new String[args.length - 1];
        if (subArgs.length > 0) {
            System.arraycopy(args, 1, subArgs, 0, subArgs.length);
        }

        int ret = command.execute(subArgs);
        System.exit(ret);
    }

    private static void showUsage(String cmd) throws Exception {
        StringBuilder builder = new StringBuilder();
        if (isEmpty(cmd)) {
            builder.append("Usage: <cmd> [option]\n");
            builder.append(String.format("%16s  %s%n", "help", "Print this message。 help <cmd> show command's help。"));

            String padding = dup(' ', 18);
            commandMap.values().forEach(v -> {
                String n    = v.name();
                String d    = v.description();
                String desc = GetOpt.formatUsageDescription(d, padding, 76);
                builder.append(String.format("%16s  %s%n", n, desc));
            });

            System.err.println(builder.toString());
        } else {
            Command command = commandMap.get(cmd);
            if (command == null) {
                System.err.println("Unknown: " + cmd);
            } else {
                command.execute("-h");
            }
        }
    }

}

