import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.DosFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Scanare {
    // Setări și liste statice
    private static final List<String> SIGNATURI_VIRUSURI = new ArrayList<>();
    private static final List<String> EXTENSII_PERICULOASE = new ArrayList<>();
    private static final List<String> EXTENSII_FOARTE_PERICULOASE = new ArrayList<>();
    private static final List<String> LOCATII_SUSPICIOASE = new ArrayList<>();
    private static final List<String> CUVINTE_CHEIE_SUSPICIOASE = new ArrayList<>();
    private static final Set<String> HASH_URI_CUNOSCUTE = new HashSet<>();
    private static final Map<String, Integer> REGULI_SCORING = new HashMap<>();
    
    // Contoare pentru statistici
    private static int fisiereScanate = 0;
    private static int fisiereSuspecte = 0;
    private static int fisierePericuloase = 0;
    
    // Pentru stocarea fișierelor suspecte și informațiilor despre ele
    private static class FisierSuspect {
        String cale;
        int scor;
        List<String> motive = new ArrayList<>();
        
        public FisierSuspect(String cale, int scor, String motiv) {
            this.cale = cale;
            this.scor = scor;
            this.motive.add(motiv);
        }
        
        public void adaugaMotiv(String motiv, int scorSuplimentar) {
            this.motive.add(motiv);
            this.scor += scorSuplimentar;
        }
        
        public String getNivelPericol() {
            if (scor >= 10) return "ÎNALT";
            if (scor >= 5) return "MEDIU";
            return "SCĂZUT";
        }
    }
    
    private static final Map<String, FisierSuspect> fisiereDetectate = new ConcurrentHashMap<>();
    
    // Inițializarea regulilor și listelor
    static {
        // Semnături comune pentru malware (doar pentru exemplificare)
        // Semnături de executabile și fișiere potențial periculoase
        SIGNATURI_VIRUSURI.add("4d5a9000"); // Semnătura executabile PE (MZ header) - Windows EXE/DLL
        SIGNATURI_VIRUSURI.add("7f454c46"); // Semnătura executabile ELF (Linux)
        SIGNATURI_VIRUSURI.add("504b0304"); // Semnătura arhive ZIP (posibile malware ascunse)
        SIGNATURI_VIRUSURI.add("cafebabe"); // Semnătura pentru fișiere Java Class

        // Adăugare semnături suplimentare executabile
        SIGNATURI_VIRUSURI.add("23212f62"); // Shebang pentru scripturi bash #!/b
        SIGNATURI_VIRUSURI.add("23212f75"); // Shebang pentru scripturi Unix #!/u
        SIGNATURI_VIRUSURI.add("3c3f7068"); // PHP Script <?ph
        SIGNATURI_VIRUSURI.add("3c68746d"); // HTML/posibil malware <htm
        SIGNATURI_VIRUSURI.add("3c736372"); // JavaScript în HTML <scr
        SIGNATURI_VIRUSURI.add("696d706f"); // Python import impo
        SIGNATURI_VIRUSURI.add("52656d6f"); // Macro VBA Remo
        SIGNATURI_VIRUSURI.add("d0cf11e0"); // Fișier Office vechi (OLE) - poate conține macro-uri
        SIGNATURI_VIRUSURI.add("2521444f"); // Adobe PDF cu JavaScript %!DO
        SIGNATURI_VIRUSURI.add("41430b00"); // Fișier Windows Help (CHM) - folosit în atacuri phishing
        SIGNATURI_VIRUSURI.add("5349502d"); // Windows Installer MSI SIP-
        SIGNATURI_VIRUSURI.add("7b5c7274"); // Format RTF (poate conține exploituri) {\rt
        SIGNATURI_VIRUSURI.add("4c000000"); // Windows LNK (shortcut) L...
        SIGNATURI_VIRUSURI.add("4a415243"); // JAR (arhivă Java) JARC
        SIGNATURI_VIRUSURI.add("377abcaf"); // 7-Zip archive (poate conține malware) 7{..
        SIGNATURI_VIRUSURI.add("25504446"); // PDF %PDF
        SIGNATURI_VIRUSURI.add("0000000c"); // JNLP (Java Web Start)
        
        // Semnături specifice malware comune (șabloane cunoscute)
        SIGNATURI_VIRUSURI.add("6575726f"); // Signatura troian euro
        SIGNATURI_VIRUSURI.add("5c756163"); // Virus WAC \uac
        SIGNATURI_VIRUSURI.add("4c6f6164"); // Signatura downloader Load
        SIGNATURI_VIRUSURI.add("54726f6a"); // String "Troj" în binar
        SIGNATURI_VIRUSURI.add("57696e64"); // WinDefender fals (string "Wind")
        SIGNATURI_VIRUSURI.add("6e657463"); // Netcat sau reverse shells (string "netc")
        SIGNATURI_VIRUSURI.add("6d657461"); // Signatura Metasploit (string "meta")
        SIGNATURI_VIRUSURI.add("68656c6c"); // Signatura hello tipică în programe ransomware
        
        // Extensii periculoase (risc mediu)
        EXTENSII_PERICULOASE.add(".exe");
        EXTENSII_PERICULOASE.add(".dll");
        EXTENSII_PERICULOASE.add(".jar");
        EXTENSII_PERICULOASE.add(".jse");
        EXTENSII_PERICULOASE.add(".msi");
        EXTENSII_PERICULOASE.add(".ocx");
        EXTENSII_PERICULOASE.add(".ps1");
        EXTENSII_PERICULOASE.add(".reg");
        
        // Extensii foarte periculoase (risc ridicat)
        EXTENSII_FOARTE_PERICULOASE.add(".bat");
        EXTENSII_FOARTE_PERICULOASE.add(".cmd");
        EXTENSII_FOARTE_PERICULOASE.add(".com");
        EXTENSII_FOARTE_PERICULOASE.add(".hta");
        EXTENSII_FOARTE_PERICULOASE.add(".msc");
        EXTENSII_FOARTE_PERICULOASE.add(".scr");
        EXTENSII_FOARTE_PERICULOASE.add(".vbs");
        EXTENSII_FOARTE_PERICULOASE.add(".pif");
        
        // Locații suspicioase pe sistem
        LOCATII_SUSPICIOASE.add("\\AppData\\Roaming\\");
        LOCATII_SUSPICIOASE.add("\\AppData\\Local\\Temp\\");
        LOCATII_SUSPICIOASE.add("\\Windows\\Temp\\");
        LOCATII_SUSPICIOASE.add("\\ProgramData\\");
        LOCATII_SUSPICIOASE.add("\\Startup\\");
        LOCATII_SUSPICIOASE.add("\\Start Menu\\Programs\\Startup\\");
        
        // Cuvinte cheie suspicioase în nume de fișiere
        CUVINTE_CHEIE_SUSPICIOASE.add("crack");
        CUVINTE_CHEIE_SUSPICIOASE.add("keygen");
        CUVINTE_CHEIE_SUSPICIOASE.add("patch");
        CUVINTE_CHEIE_SUSPICIOASE.add("hack");
        CUVINTE_CHEIE_SUSPICIOASE.add("trojan");
        CUVINTE_CHEIE_SUSPICIOASE.add("warez");
        CUVINTE_CHEIE_SUSPICIOASE.add("virus");
        CUVINTE_CHEIE_SUSPICIOASE.add("malware");
        CUVINTE_CHEIE_SUSPICIOASE.add("exploit");
        CUVINTE_CHEIE_SUSPICIOASE.add("rootkit");
        CUVINTE_CHEIE_SUSPICIOASE.add("keylogger");
        CUVINTE_CHEIE_SUSPICIOASE.add("spyware");
        CUVINTE_CHEIE_SUSPICIOASE.add("backdoor");
        CUVINTE_CHEIE_SUSPICIOASE.add("activator");
        CUVINTE_CHEIE_SUSPICIOASE.add("invoice");
        CUVINTE_CHEIE_SUSPICIOASE.add("payment");
        CUVINTE_CHEIE_SUSPICIOASE.add("account");
        CUVINTE_CHEIE_SUSPICIOASE.add("update");
        
        // Configurarea scorurilor pentru regulile de heuristici
        REGULI_SCORING.put("EXTENSIE_PERICULOASA", 2);
        REGULI_SCORING.put("EXTENSIE_FOARTE_PERICULOASA", 3);
        REGULI_SCORING.put("LOCATIE_SUSPICIOASA", 2);
        REGULI_SCORING.put("CUVINTE_CHEIE_SUSPICIOASE", 2);
        REGULI_SCORING.put("SEMNATURA_VIRUS", 10);
        REGULI_SCORING.put("HASH_CUNOSCUT", 10);
        REGULI_SCORING.put("ASCUNS", 3);
        REGULI_SCORING.put("DIMENSIUNE_SUSPECTA", 1);
        REGULI_SCORING.put("MODIFICAT_RECENT", 2);
        REGULI_SCORING.put("MASCARE_EXTENSIE", 4);
        REGULI_SCORING.put("PERMISIUNE_EXECUTIE", 1);
    }
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== SCANARE AVANSATĂ MALWARE ===");
        System.out.println("Introduceți calea directorului pentru scanare (ex: C:\\Users\\nume):");
        String dirPath = scanner.nextLine();
        
        // Verificare dacă directorul există
        File dirToScan = new File(dirPath);
        if (!dirToScan.exists() || !dirToScan.isDirectory()) {
            System.out.println("EROARE: Directorul specificat nu există sau nu este un director valid!");
            scanner.close();
            return;
        }
        
        System.out.println("\nSelectați modul de scanare:");
        System.out.println("1. Scanare rapidă (doar locații comune pentru malware)");
        System.out.println("2. Scanare standard (toate fișierele, verificări de bază)");
        System.out.println("3. Scanare avansată (toate fișierele, toate verificările)");
        
        // Citim modul de scanare și îl stocăm într-o variabilă finală 
        // pentru a putea fi folosit în lambda expressions
        final int modScanareTmp;
        try {
            int input = Integer.parseInt(scanner.nextLine());
            if (input < 1 || input > 3) {
                modScanareTmp = 2;
                System.out.println("Opțiune invalidă, se va folosi scanarea standard.");
            } else {
                modScanareTmp = input;
            }
        } catch (NumberFormatException e) {
            modScanareTmp = 2;
            System.out.println("Opțiune invalidă, se va folosi scanarea standard.");
        }
        final int modScanare = modScanareTmp; // Variabilă finală pentru lambda expressions
        
        System.out.println("\nÎncepere scanare în: " + dirPath);
        System.out.println("Mod scanare: " + (modScanare == 1 ? "Rapidă" : (modScanare == 2 ? "Standard" : "Avansată")));
        System.out.println("Vă rugăm așteptați, scanarea poate dura câteva minute...\n");
        
        long startTime = System.currentTimeMillis();
        
        try {
            Path startingDir = Paths.get(dirPath);
            
            if (modScanare == 3) {
                // Pentru scanare avansată, folosim multi-threading
                int numThreads = Runtime.getRuntime().availableProcessors();
                final ExecutorService executor = Executors.newFixedThreadPool(numThreads);
                System.out.println("Scanare paralelă cu " + numThreads + " thread-uri...");
                
                Files.walkFileTree(startingDir, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        executor.execute(() -> {
                            try {
                                scanareFisier(file.toFile(), modScanare);
                            } catch (Exception e) {
                                System.out.println("Eroare la scanarea fișierului " + file + ": " + e.getMessage());
                                e.printStackTrace();
                            }
                        });
                        return FileVisitResult.CONTINUE;
                    }
                    
                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        System.out.println("Nu s-a putut accesa: " + file.toString() + " - " + exc.getMessage());
                        return FileVisitResult.CONTINUE;
                    }
                });
                
                executor.shutdown();
                try {
                    executor.awaitTermination(1, TimeUnit.HOURS);
                } catch (InterruptedException e) {
                    System.out.println("Scanarea a fost întreruptă!");
                    e.printStackTrace();
                }
            } else {
                // Pentru scanare rapidă și standard, folosim single-thread
                Files.walkFileTree(startingDir, new SimpleFileVisitor<Path>() {
                    @Override
                    public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                        // Pentru scanare rapidă, verificăm doar locațiile suspicioase
                        if (modScanare == 1) {
                            String caleFisier = file.toString().toLowerCase();
                            boolean inLocatieSuspicioasa = false;
                            
                            for (String locatie : LOCATII_SUSPICIOASE) {
                                if (caleFisier.contains(locatie.toLowerCase())) {
                                    inLocatieSuspicioasa = true;
                                    break;
                                }
                            }
                            
                            if (!inLocatieSuspicioasa) {
                                return FileVisitResult.CONTINUE;
                            }
                        }
                        
                        try {
                            scanareFisier(file.toFile(), modScanare);
                        } catch (Exception e) {
                            System.out.println("Eroare la scanarea fișierului " + file + ": " + e.getMessage());
                            e.printStackTrace();
                        }
                        return FileVisitResult.CONTINUE;
                    }
                    
                    @Override
                    public FileVisitResult visitFileFailed(Path file, IOException exc) {
                        System.out.println("Nu s-a putut accesa: " + file.toString() + " - " + exc.getMessage());
                        return FileVisitResult.CONTINUE;
                    }
                });
            }
            
            long endTime = System.currentTimeMillis();
            long durataScanare = (endTime - startTime) / 1000;
            
            System.out.println("\n=== REZULTATE SCANARE ===");
            System.out.println("Fișiere scanate: " + fisiereScanate);
            System.out.println("Fișiere suspecte detectate: " + fisiereSuspecte);
            System.out.println("Fișiere potențial periculoase: " + fisierePericuloase);
            System.out.println("Durată scanare: " + durataScanare + " secunde");
            
            if (!fisiereDetectate.isEmpty()) {
                System.out.println("\nDetalii fișiere suspecte:");
                System.out.println("----------------------------------------------------------");
                
                // Afișăm fișierele suspecte sortate după scorul de pericol
                fisiereDetectate.values().stream()
                    .sorted((f1, f2) -> Integer.compare(f2.scor, f1.scor)) // Sortare descrescătoare după scor
                    .forEach(fisier -> {
                        System.out.println("Fișier: " + fisier.cale);
                        System.out.println("Nivel de pericol: " + fisier.getNivelPericol() + " (" + fisier.scor + " puncte)");
                        System.out.println("Motive:");
                        for (String motiv : fisier.motive) {
                            System.out.println("  - " + motiv);
                        }
                        System.out.println("----------------------------------------------------------");
                    });
                
                // Salvăm rezultatele în fișier
                try {
                    Path outputFile = Paths.get("rezultate_scanare_" + new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date()) + ".txt");
                    List<String> linii = new ArrayList<>();
                    
                    linii.add("=== REZULTATE SCANARE MALWARE ===");
                    linii.add("Data scanării: " + new SimpleDateFormat("dd/MM/yyyy HH:mm:ss").format(new Date()));
                    linii.add("Fișiere scanate: " + fisiereScanate);
                    linii.add("Fișiere suspecte: " + fisiereSuspecte);
                    linii.add("Fișiere potențial periculoase: " + fisierePericuloase);
                    linii.add("Durată scanare: " + durataScanare + " secunde");
                    linii.add("\n=== DETALII FIȘIERE SUSPECTE ===");
                    
                    fisiereDetectate.values().stream()
                        .sorted((f1, f2) -> Integer.compare(f2.scor, f1.scor))
                        .forEach(fisier -> {
                            linii.add("\nFișier: " + fisier.cale);
                            linii.add("Nivel de pericol: " + fisier.getNivelPericol() + " (" + fisier.scor + " puncte)");
                            linii.add("Motive:");
                            for (String motiv : fisier.motive) {
                                linii.add("  - " + motiv);
                            }
                        });
                    
                    Files.write(outputFile, linii);
                    System.out.println("\nRezultatele au fost salvate în fișierul: " + outputFile.toAbsolutePath());
                } catch (IOException e) {
                    System.out.println("Eroare la salvarea rezultatelor: " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
        } catch (IOException e) {
            System.out.println("Eroare în timpul scanării: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("Eroare neașteptată: " + e.getMessage());
            e.printStackTrace();
        }
        
        scanner.close();
    }
    
    private static synchronized void scanareFisier(File fisier, int modScanare) {
        if (!fisier.exists()) {
            System.out.println("AVERTISMENT: Fișierul nu există: " + fisier.getAbsolutePath());
            return;
        }
        
        if (!fisier.canRead()) {
            System.out.println("AVERTISMENT: Nu se poate citi fișierul: " + fisier.getAbsolutePath());
            return;
        }
        
        fisiereScanate++;
        
        if (fisiereScanate % 100 == 0) {
            System.out.println("Scanare în progres... " + fisiereScanate + " fișiere verificate.");
        }
        
        try {
            Path path = fisier.toPath();
            BasicFileAttributes attrs = Files.readAttributes(path, BasicFileAttributes.class);
            int scorPericol = 0;
            List<String> motive = new ArrayList<>();
            
            // 1. Verificare extensii periculoase
            String numeFisier = fisier.getName().toLowerCase();
            
            for (String ext : EXTENSII_PERICULOASE) {
                if (numeFisier.endsWith(ext)) {
                    scorPericol += REGULI_SCORING.get("EXTENSIE_PERICULOASA");
                    motive.add("Extensie potențial periculoasă: " + ext);
                    break;
                }
            }
            
            for (String ext : EXTENSII_FOARTE_PERICULOASE) {
                if (numeFisier.endsWith(ext)) {
                    scorPericol += REGULI_SCORING.get("EXTENSIE_FOARTE_PERICULOASA");
                    motive.add("Extensie foarte periculoasă: " + ext);
                    break;
                }
            }
            
            // 2. Verificare locație suspicioasă
            String caleFisier = fisier.getAbsolutePath().toLowerCase();
            for (String locatie : LOCATII_SUSPICIOASE) {
                if (caleFisier.contains(locatie.toLowerCase())) {
                    scorPericol += REGULI_SCORING.get("LOCATIE_SUSPICIOASA");
                    motive.add("Locație suspicioasă: " + locatie);
                    break;
                }
            }
            
            // 3. Verificare cuvinte cheie suspicioase în nume
            for (String cuvant : CUVINTE_CHEIE_SUSPICIOASE) {
                if (numeFisier.contains(cuvant.toLowerCase())) {
                    scorPericol += REGULI_SCORING.get("CUVINTE_CHEIE_SUSPICIOASE");
                    motive.add("Nume suspect: conține '" + cuvant + "'");
                    break;
                }
            }
            
            // 4. Verificare mascare extensie (ex: document.txt.exe)
            Pattern pattern = Pattern.compile("\\.(\\w+)\\.(exe|bat|cmd|ps1|vbs|js|jar|msi|scr|com)$");
            Matcher matcher = pattern.matcher(numeFisier);
            if (matcher.find()) {
                scorPericol += REGULI_SCORING.get("MASCARE_EXTENSIE");
                motive.add("Posibilă mascare de extensie: ." + matcher.group(1) + "." + matcher.group(2));
            }
            
            // 5. Verificare dacă fișierul este ascuns
            try {
                DosFileAttributes dosAttrs = Files.readAttributes(path, DosFileAttributes.class);
                if (dosAttrs.isHidden()) {
                    scorPericol += REGULI_SCORING.get("ASCUNS");
                    motive.add("Fișier ascuns");
                }
            } catch (UnsupportedOperationException | IOException e) {
                // Ignorăm dacă nu putem citi atributele DOS
                System.out.println("Nu s-au putut citi atributele DOS pentru: " + fisier.getAbsolutePath());
            }
            
            // 6. Verificare dimensiune suspicioasă (< 100KB pentru executabile)
            if ((numeFisier.endsWith(".exe") || numeFisier.endsWith(".dll") || 
                 numeFisier.endsWith(".scr")) && fisier.length() < 102400) {
                scorPericol += REGULI_SCORING.get("DIMENSIUNE_SUSPECTA");
                motive.add("Dimensiune suspicioasă: " + (fisier.length() / 1024) + " KB");
            }
            
            // 7. Verificare dacă fișierul a fost modificat recent
            LocalDateTime lastModified = LocalDateTime.ofInstant(
                Instant.ofEpochMilli(attrs.lastModifiedTime().toMillis()),
                ZoneId.systemDefault());
            
            if (ChronoUnit.HOURS.between(lastModified, LocalDateTime.now()) < 24) {
                scorPericol += REGULI_SCORING.get("MODIFICAT_RECENT");
                motive.add("Modificat în ultimele 24 de ore");
            }
            
            // 8. Verificare avansată semnături pentru fișiere de dimensiune rezonabilă
            if (modScanare > 1 && fisier.length() < 10_000_000) {
                try {
                    String signatura = calculareHashPrimiiBytes(fisier);
                    if (signatura != null && esteSignaturaVirus(signatura)) {
                        scorPericol += REGULI_SCORING.get("SEMNATURA_VIRUS");
                        motive.add("Conține semnătură suspectă: " + signatura);
                    }
                } catch (Exception e) {
                    System.out.println("Eroare la verificarea semnăturii pentru: " + fisier.getAbsolutePath() + " - " + e.getMessage());
                }
                
                // 9. Verificare hash complet pentru scanare avansată
                if (modScanare == 3 && fisier.length() < 50_000_000) {
                    try {
                        String hashComplet = calculareMD5(fisier);
                        if (HASH_URI_CUNOSCUTE.contains(hashComplet)) {
                            scorPericol += REGULI_SCORING.get("HASH_CUNOSCUT");
                            motive.add("Hash cunoscut ca periculos: " + hashComplet);
                        }
                    } catch (Exception e) {
                        System.out.println("Eroare la calculul hash-ului pentru: " + fisier.getAbsolutePath() + " - " + e.getMessage());
                    }
                }
            }
            
            // Dacă scorul depășește pragul, marcăm fișierul ca suspect
            if (scorPericol >= 3) {
                adaugaFisierSuspect(fisier.getAbsolutePath(), scorPericol, motive);
            }
            
        } catch (IOException e) {
            System.out.println("Eroare la accesarea fișierului: " + fisier.getAbsolutePath() + " - " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Eroare neașteptată la scanarea fișierului: " + fisier.getAbsolutePath() + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static synchronized void adaugaFisierSuspect(String caleFisier, int scor, List<String> motive) {
        if (motive.isEmpty()) {
            System.out.println("AVERTISMENT: Lista de motive este goală pentru: " + caleFisier);
            return;
        }
        
        FisierSuspect fisier = new FisierSuspect(caleFisier, scor, motive.get(0));
        
        // Adăugăm toate motivele începând cu al doilea (primul e adăugat în constructor)
        for (int i = 1; i < motive.size(); i++) {
            fisier.adaugaMotiv(motive.get(i), 0); // 0 pentru că scorul e deja calculat
        }
        
        fisiereDetectate.put(caleFisier, fisier);
        fisiereSuspecte++;
        
        if (scor >= 5) {
            fisierePericuloase++;
        }
    }
    
    private static String calculareHashPrimiiBytes(File fisier) throws IOException {
        try {
            byte[] buffer = new byte[4]; // Citim primii 4 bytes pentru semnătură
            
            if (Files.size(fisier.toPath()) >= 4) {
                byte[] data = Files.readAllBytes(fisier.toPath());
                System.arraycopy(data, 0, buffer, 0, 4);
                return byteArrayToHex(buffer).toLowerCase();
            }
        } catch (IOException e) {
            System.out.println("Eroare la citirea primilor bytes din fișierul: " + fisier.getAbsolutePath());
            throw e;
        }
        return null;
    }
    
    private static String calculareMD5(File fisier) throws IOException, NoSuchAlgorithmException {
        try {
            byte[] data = Files.readAllBytes(fisier.toPath());
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(data);
            byte[] digest = md.digest();
            return byteArrayToHex(digest).toLowerCase();
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println("Eroare la calcularea MD5 pentru fișierul: " + fisier.getAbsolutePath());
            throw e;
        }
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
        for (String sig : SIGNATURI_VIRUSURI) {
            if (signatura.startsWith(sig)) {
                return true;
            }
        }
        return false;
    }
}
