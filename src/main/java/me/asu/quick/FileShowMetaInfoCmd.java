package me.asu.quick;


import static me.asu.quick.ErrorCode.*;
import static me.asu.quick.util.PBEUtils.readGzeMetaInfo;
import static me.asu.quick.util.StringUtils.isEmpty;
import static me.asu.quick.util.StringUtils.readPassword;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import me.asu.quick.util.GetOpt;

public class FileShowMetaInfoCmd implements Command {

    String              name        = "show";
    String              optString   = "hp:";
    Map<String, String> description = new TreeMap<>();

    {
        description.put("-h", "Print this message");
        description.put("-p", "The password.");
        description.put("[arguments]", "The encrypted files or directories.");
    }

    public String name() {
        return name;
    }

    public String description() {
        return "Show the meta infomation of the encrypted file.";
    }

    public int execute(String[] args) throws Exception {
        GetOpt opt = new GetOpt(args, optString);
        int c;

        String pass = null;
        while ((c = opt.getNextOption()) != -1) {
            switch (c) {
                case 'h':
                    opt.printUsage(name, description);
                    System.exit(OK);
                    break;
                case 'p':
                    pass = opt.getOptionArg();
                    break;
            }
        }
        String[] cmdArgs = opt.getCmdArgs();
        if (isEmpty(pass)) {
            try {
                pass = readPassword();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(UNKNOWN_ERROR);
            }
        }

        if (cmdArgs == null || cmdArgs.length == 0) {
            System.out.println(description());
            opt.printUsage(name(), description);
            System.exit(1);
        }
        List<Path> pathList= new ArrayList<>();
        findFiles(cmdArgs, pathList);
        for (Path path : pathList) {
            Map<String, String> map = readGzeMetaInfo(path, pass);
            if (map.isEmpty()) continue;
            String version = map.remove("version");
            System.out.println("version: "+ version);
            map.forEach((k,v)->{
                System.out.printf("%s: %s%n",k, v);
            });
            System.out.println("------------------------");
        }
        return OK;
    }

    private void findFiles(String[] cmdArgs, List<Path> pathList)
    throws IOException {
        for (String cmdArg : cmdArgs) {
            Path p = Paths.get(cmdArg);
            if (Files.isDirectory(p)) {
                Files.walkFileTree(p, new SimpleFileVisitor<Path>(){
                    @Override
                    public FileVisitResult visitFile(Path file,
                            BasicFileAttributes attrs) throws IOException {
                        if (file.toString().endsWith(".gzb")) pathList.add(file);
                        return FileVisitResult.CONTINUE;
                    }
                });
            } else {
                if (p.toString().endsWith(".gzb")) pathList.add(p);
            }
        }
    }

    public static void main(String[] args) throws Exception {
        new FileShowMetaInfoCmd()
                .execute(new String[]{"-p", "12345678", "target"});
    }
}
