package Scan;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class scan {
    private static final List<String> semnaturaMalware = new ArrayList<>();
    private static int fisiereScanate = 0;
    private static int fisiereSuspecte = 0;

    // Semnături simple pentru demonstrație
    static {
        // Semnături comune pentru malware (doar pentru exemplificare)
        semnaturaMalware.add("4d5a9000"); // Semnătura executabile PE
        semnaturaMalware.add("7f454c46"); // Semnătura executabile ELF
        semnaturaMalware.add("504b0304"); // Semnătura arhive ZIP (posibile malware ascunse)
        semnaturaMalware.add("cafebabe"); // Semnătura pentru fișiere Java Class

        // Adăugare semnături suplimentare executabile
        semnaturaMalware.add("23212f62"); // Shebang pentru scripturi bash #!/b
        semnaturaMalware.add("23212f75"); // Shebang pentru scripturi Unix #!/u
        semnaturaMalware.add("3c3f7068"); // PHP Script <?ph
        semnaturaMalware.add("3c68746d"); // HTML/posibil malware <htm
        semnaturaMalware.add("3c736372"); // JavaScript în HTML <scr
        semnaturaMalware.add("696d706f"); // Python import impo
        semnaturaMalware.add("52656d6f"); // Macro VBA Remo
        semnaturaMalware.add("d0cf11e0"); // Fișier Office vechi (OLE) - poate conține macro-uri
        semnaturaMalware.add("2521444f"); // Adobe PDF cu JavaScript %!DO
        semnaturaMalware.add("41430b00"); // Fișier Windows Help (CHM) - folosit în atacuri phishing
        semnaturaMalware.add("5349502d"); // Windows Installer MSI SIP-
        semnaturaMalware.add("7b5c7274"); // Format RTF (poate conține exploituri) {\rt
        semnaturaMalware.add("4c000000"); // Windows LNK (shortcut) L...
        semnaturaMalware.add("4a415243"); // JAR (arhivă Java) JARC - corectat
        semnaturaMalware.add("377abcaf"); // 7-Zip archive (poate conține malware) 7{..
        semnaturaMalware.add("25504446"); // PDF %PDF - corectat
        semnaturaMalware.add("0000000c"); // JNLP (Java Web Start) - corectat

        // Semnături specifice malware comune (șabloane cunoscute)
        semnaturaMalware.add("6575726f"); // Signatura troian euro - corectat
        semnaturaMalware.add("4c6f6164"); // Signatura downloader Load - corectat
        semnaturaMalware.add("54726f6a"); // String "Troj" în binar
        semnaturaMalware.add("57696e64"); // WinDefender fals (string "Wind")
        semnaturaMalware.add("6e657463"); // Netcat sau reverse shells (string "netc") - corectat
        semnaturaMalware.add("6d657461"); // Signatura Metasploit (string "meta") - corectat
        semnaturaMalware.add("68656c6c"); // Signatura hello tipică în programe ransomware - corectat
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== SCANARE MALWARE ===");
        System.out.println("Introduceți calea directorului pentru scanare (ex: C:\\Users\\nume):");
        String dirPath = scanner.nextLine();

        System.out.println("\nÎncepere scanare în: " + dirPath);
        System.out.println("Vă rugăm așteptați, scanarea poate dura câteva minute...\n");

        try {
            Path startingDir = Paths.get(dirPath);
            Files.walkFileTree(startingDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    scanareFisier(file.toFile());
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    System.out.println("Nu s-a putut accesa: " + file.toString());
                    return FileVisitResult.CONTINUE;
                }
            });

            System.out.println("\n=== REZULTATE SCANARE ===");
            System.out.println("Fișiere scanate: " + fisiereScanate);
            System.out.println("Fișiere suspecte detectate: " + fisiereSuspecte);

        } catch (IOException e) {
            System.out.println("Eroare în timpul scanării: " + e.getMessage());
        }

        scanner.close();
    }

    private static void scanareFisier(File fisier) {
        fisiereScanate++;

        if (fisiereScanate % 100 == 0) {
            System.out.println("Scanare în progres... " + fisiereScanate + " fișiere verificate.");
        }

        // Verificare extensii periculoase
        if (areExtensiePericuloasa(fisier)) {
            System.out.println("[SUSPECT] Extensie potențial periculoasă: " + fisier.getAbsolutePath());
            fisiereSuspecte++;
            return;
        }

        // Scanare conținut fișier pentru semnături
        if (fisier.length() < 10_000_000) { // Scanăm doar fișiere mai mici de 10MB
            try {
                String signatura = calculareHashPrimiiBytes(fisier);
                if (signatura != null && esteSignaturaVirus(signatura)) {
                    System.out.println("[PERICOL] Posibil malware detectat: " + fisier.getAbsolutePath());
                    fisiereSuspecte++;
                }
            } catch (Exception e) {
                // Ignorăm erorile la deschiderea fișierelor
            }
        }
    }

    private static boolean areExtensiePericuloasa(File fisier) {
        String nume = fisier.getName().toLowerCase();
        return nume.endsWith(".exe") || nume.endsWith(".dll") ||
                nume.endsWith(".bat") || nume.endsWith(".cmd") ||
                nume.endsWith(".scr") || nume.endsWith(".vbs") ||
                nume.endsWith(".js") || nume.endsWith(".jar");
    }

    private static String calculareHashPrimiiBytes(File fisier) {
        try {
            byte[] buffer = new byte[4]; // Citim primii 4 bytes pentru semnătură

            if (Files.size(fisier.toPath()) >= 4) {
                byte[] data = Files.readAllBytes(fisier.toPath());
                System.arraycopy(data, 0, buffer, 0, 4);

                MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(buffer);
                byte[] digest = md.digest();
                return byteArrayToHex(buffer).toLowerCase();
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            // Ignorăm erorile
        }
        return null;
    }

    // Metodă pentru convertirea unui array de bytes în format hexazecimal
    private static String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static boolean esteSignaturaVirus(String signatura) {
        for (String sig : semnaturaMalware) {
            if (signatura.startsWith(sig)) {
                return true;
            }
        }
        return false;
    }
}
