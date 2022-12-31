package me.asu.quick;


import static me.asu.quick.ErrorCode.IO_ERROR;
import static me.asu.quick.ErrorCode.OK;
import static me.asu.quick.ErrorCode.PARAM_REQUIRED_ERROR;
import static me.asu.quick.ErrorCode.UNKNOWN_ERROR;
import static me.asu.quick.util.PBEUtils.decryptToGzbFile;
import static me.asu.quick.util.StringUtils.isEmpty;
import static me.asu.quick.util.StringUtils.readPassword;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import me.asu.quick.util.GetOpt;

public class FileDecryptCmd implements Command{

    String              name        = "decrypt";
    String              optString   = "ho:p:";
    Map<String, String> description = new TreeMap<>();

    {
        description.put("-h", "Print this message");
        description.put("-p", "The password.");
        description.put("-o", "The output directory");
        description.put("[arguments]", "The encrypted files or directories.");
    }

    public String name() {
        return name;
    }

    public String description() {
        return "Decrypt file.";
    }

    public int execute(String[] args) throws Exception {
        GetOpt opt = new GetOpt(args, optString);
        int c;

        String pass = null;
        String output = null;
        while ((c = opt.getNextOption()) != -1) {
            switch (c) {
                case 'h':
                    opt.printUsage(name, description);
                    System.exit(OK);
                    break;
                case 'o':
                    output = opt.getOptionArg();
                    break;

                case 'p':
                    pass = opt.getOptionArg();
                    break;

            }
        }

        if (isEmpty(pass)) {
            try {
                pass = readPassword();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(UNKNOWN_ERROR);
            }
        }
        if (isEmpty(output)) {
            System.out.println(description());
            opt.printUsage(name, description);
            System.exit(PARAM_REQUIRED_ERROR);
        }

        Path dir = Paths.get(output);
        if (!Files.isDirectory(dir)) {
            Files.createDirectories(dir);
        }
        // the input files
        String[] cmdArgs = opt.getCmdArgs();
        List<Path> pathList = new ArrayList<>();
        findFiles(cmdArgs, pathList);
        if (pathList.isEmpty()) {
            System.out.println(description());
            opt.printUsage(name, description);
            System.exit(PARAM_REQUIRED_ERROR);
        }
        for (Path path : pathList) {
            // 解密
            Path outputPath =  decryptToGzbFile(path, dir, pass);
        }

        return OK;
    }

    private void findFiles(String[] cmdArgs, List<Path> pathList)
    throws IOException {
        for (String cmdArg : cmdArgs) {
            Path p = Paths.get(cmdArg);
            if (Files.isDirectory(p)) {
                Files.walkFileTree(p, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file,
                            BasicFileAttributes attrs) throws IOException {
                        if (file.toString().endsWith(".gzb")) {
                            pathList.add(file);
                        }
                        return FileVisitResult.CONTINUE;
                    }
                });
            } else {
                if (p.toString().endsWith(".gzb")) { pathList.add(p); }
            }
        }
    }

    private void writeToFile(String output, byte[] data) {
        try {
            Path path = Paths.get(output);
            Path parent = path.getParent();
            if (!Files.isDirectory(path)) {
                Files.createDirectories(parent);
            }
            Files.write(path, data);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(IO_ERROR);
        }
    }

    public static void main(String[] args) throws Exception {
        new FileDecryptCmd().execute(new String[]{"-p", "12345678", "-o", "target",
        "target"});
    }

}
