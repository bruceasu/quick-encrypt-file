package me.asu.quick;

import static me.asu.quick.ErrorCode.FILE_NOT_FOUND_ERROR;
import static me.asu.quick.ErrorCode.OK;
import static me.asu.quick.ErrorCode.PARAM_ERROR;
import static me.asu.quick.ErrorCode.PARAM_REQUIRED_ERROR;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import me.asu.quick.util.GetOpt;

public class FileCopyCmd implements Command {

    String              name        = "cp";
    String              optString   = "hv";
    boolean             verbose     = false;
    Map<String, String> description = new TreeMap<>();

    {
        description.put("-h", "Print this message.");
        description.put("[arguments]", "The input files or directories."
                + " The last is the target. if copy many files, the targets should be a directory.");
    }

    public String name() {
        return name;
    }

    public String description() {
        return "Copy files.";
    }

    public int execute(String[] args) throws Exception {
        GetOpt opt = new GetOpt(args, optString);
        int c;

        while ((c = opt.getNextOption()) != -1) {
            switch (c) {
                case 'h':
                    opt.printUsage(name, description);
                    System.exit(OK);
                    break;
                case 'v':
                    verbose = true;
                    break;
            }
        }
        String[] cmdArgs = opt.getCmdArgs();
        if (cmdArgs == null || cmdArgs.length < 2) {
            System.out.println(description());
            opt.printUsage(name, description);
            System.exit(PARAM_REQUIRED_ERROR);
        }

        String output = cmdArgs[cmdArgs.length - 1];
        Path outputPath = Paths.get(output);

        if (outputPath.getParent() != null
                && !Files.isDirectory(outputPath.getParent())) {
            Files.createDirectories(outputPath.getParent());
        }

        List<Path> pathList = new ArrayList<>();
        String[] checkPath = new String[cmdArgs.length - 1];
        System.arraycopy(cmdArgs, 0, checkPath, 0, checkPath.length);
        if (checkPath.length > 1) {
            // output should be a directory
            if (Files.isRegularFile(outputPath)) {
                System.err.println("The last parameter should be a directory");
                return PARAM_ERROR;
            }
            if (!Files.isDirectory(outputPath)) {
                Files.createDirectories(outputPath);
            }
            for (String s : checkPath) {
                pathList.clear();
                findFiles(s, pathList);
                for (Path path : pathList) {
                    Path target = mkOutput(Paths.get(s), path, outputPath);
                    copyToFile(path, target);
                }
            }

        } else {
            Path inPath = Paths.get(checkPath[0]);
            if (Files.isRegularFile(inPath)) {
                if (Files.isDirectory(outputPath)) {
                    final Path path = Paths.get(output, inPath.getFileName()
                                                              .toString());
                    copyToFile(inPath, path);
                } else {
                    // is file
                    copyToFile(inPath, outputPath);
                }

            } else if (Files.isDirectory(inPath)) {
                // output should be a directory
                if (Files.isRegularFile(outputPath)) {
                    System.err.println("The last parameter should be a directory");
                    return PARAM_ERROR;
                }
                if (!Files.isDirectory(outputPath)) {
                    Files.createDirectories(outputPath);
                }
                findFiles(checkPath[0], pathList);
                for (Path path : pathList) {
                    Path target = mkOutput(inPath, path, outputPath);
                    copyToFile(path, target);
                }
            } else if (!Files.exists(inPath)) {
                return FILE_NOT_FOUND_ERROR;
            }
        }

        return OK;
    }

    private Path mkOutput(Path s, Path path, Path outputPath) {
        final Path relativize = s.relativize(path);
        if (relativize.toString().equals("")) {
            return outputPath.resolve(path.getFileName());
        } else {
            return outputPath.resolve(relativize);
        }
    }

    private void copyToFile(Path path, Path outputPath) throws IOException {
        if (verbose) {
            System.out.printf("Coping %s to %s.%n", path, outputPath);
        }
        if (!Files.isRegularFile(path)) {
            System.err.printf("%s is not a file or is not exist. %n", path);
            return;
        }
        final Path parent = outputPath.toAbsolutePath().getParent();
        if (!Files.isDirectory(parent)) {
            Files.createDirectories(parent);
        }
        Files.copy(path, outputPath, StandardCopyOption.COPY_ATTRIBUTES, StandardCopyOption.REPLACE_EXISTING);

//        final FileChannel inCh = FileChannel.open(path, StandardOpenOption.READ);
//        final FileChannel outCh = FileChannel.open(outputPath,
//                StandardOpenOption.WRITE,
//                StandardOpenOption.READ,
//                StandardOpenOption.CREATE
//        );
//        inCh.transferTo(0, inCh.size(), outCh);
//        // 等价
//        //outCh.transferFrom(inCh,0, inCh.size());
    }

    private void findFiles(String base, List<Path> pathList)
    throws IOException {
        Path p = Paths.get(base);
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
            pathList.add(p);
        }
    }

    public static void main(String[] args) throws Exception {
        final long s = System.currentTimeMillis();
        new FileCopyCmd().execute(new String[]{"D:\\12_fonts\\仓耳今楷",
                "target\\tmp"});
        final long e = System.currentTimeMillis();
        System.out.println("Cost: " + (e - s) + " ms.");
    }
}
