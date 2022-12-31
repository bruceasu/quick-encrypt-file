package me.asu.quick.util;

import java.awt.HeadlessException;
import java.io.Console;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;

public class StringUtils {

    public static boolean isEmpty(String input) {
        return input == null || input.isEmpty();
    }

    public static boolean isBlank(String input) {
        return input == null || input.trim().isEmpty();
    }

    public static String dup(char c, int i) {
        if (i <= 0) { return ""; }
        if (i == 1) { return "" + c; }
        StringBuilder b = new StringBuilder();
        for (int j = 0; j < i; j++) {
            b.append(c);
        }
        return b.toString();
    }

    public static String readPassword() throws Exception {
        Console console = System.console();
        String  prompt  = "Input the password: ";
        if (console == null) {
            try {
                JPanel         panel = new JPanel();
                JLabel         label = new JLabel(prompt);
                JPasswordField pass  = new JPasswordField(10);
                panel.add(label);
                panel.add(pass);
                String[] options = new String[]{"OK", "CANCEL"};
                int option = JOptionPane
                        .showOptionDialog(null, panel, "PASSWORD",
                                JOptionPane.NO_OPTION,
                                JOptionPane.PLAIN_MESSAGE, null, options,
                                options[1]);
                if (option == 0) { // pressing OK button
                    char[] password = pass.getPassword();
                    return new String(password);
                }
                return "";
            } catch (HeadlessException e) {
                StringBuilder builder = new StringBuilder();
                String        pw      = null;
                do {
                    System.out.println(prompt);
                    int read = System.in.read();
                    if (read == '\n') {
                        pw = builder.toString();
                    } else {
                        builder.append(read);
                        System.out.print("\b");
                    }
                } while (isEmpty(pw));
                return pw;
            }
        } else {
            return new String(console.readPassword(prompt));
        }
    }

}
