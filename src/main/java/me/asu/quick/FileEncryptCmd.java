package me.asu.quick;

import static me.asu.quick.ErrorCode.IO_ERROR;
import static me.asu.quick.ErrorCode.OK;
import static me.asu.quick.ErrorCode.PARAM_REQUIRED_ERROR;
import static me.asu.quick.ErrorCode.UNKNOWN_ERROR;
import static me.asu.quick.util.PBEUtils.encryptToGzbFile;
import static me.asu.quick.util.StringUtils.isEmpty;
import static me.asu.quick.util.StringUtils.readPassword;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Base64.Encoder;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import me.asu.quick.util.GetOpt;

public class FileEncryptCmd implements Command {

    String              name        = "encrypt";
    String              optString   = "hp:o:";
    Map<String, String> description = new TreeMap<>();

    {
        description.put("-h", "Print this message.");
        description.put("-o", "The output directory");
        description.put("-p", "The password.");
        description.put("[arguments]", "The input files or directories.");
    }

    public String name() {
        return name;
    }

    public String description() {
        return "Encrypt file.";
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
        Path outputPath = Paths.get(output);
        if (!Files.isDirectory(outputPath.getParent())) {
            Files.createDirectories(outputPath.getParent());
        }

        String[] cmdArgs = opt.getCmdArgs();
        if (cmdArgs == null || cmdArgs.length == 0) {
            System.out.println(description());
            opt.printUsage(name, description);
            System.exit(PARAM_REQUIRED_ERROR);
        }
        List<Path> pathList = new ArrayList<>();
        findFiles(cmdArgs, pathList);
        for (Path p : pathList) {
            Path target = encryptToGzbFile(p, outputPath, "12345678");
        }
        return OK;
    }

    private void writeToFile(String output,
            byte[] encrypt,
            Encoder mimeEncoder) {
        try {
            Path path = Paths.get(output);
            Path parent = path.getParent();
            if (!Files.isDirectory(path)) {
                Files.createDirectories(parent);
            }
            byte[] data = mimeEncoder.encode(encrypt);
            Files.write(path, data);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(IO_ERROR);
        }
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
                        pathList.add(file);
                        return FileVisitResult.CONTINUE;
                    }
                });
            } else {
                if (p.toString().endsWith(".gzb")) { pathList.add(p); }
            }
        }
    }
}
