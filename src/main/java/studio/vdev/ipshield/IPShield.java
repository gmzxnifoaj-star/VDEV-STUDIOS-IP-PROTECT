package studio.vdev.ipshield;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.*;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.*;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.text.SimpleDateFormat;
import java.util.*;

public class IPShield extends JavaPlugin implements Listener {

    private File dataFile;
    private File logFile;
    private YamlConfiguration data;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        dataFile = new File(getDataFolder(), "data.yml");
        logFile = new File(getDataFolder(), "logs.txt");
        data = YamlConfiguration.loadConfiguration(dataFile);
        getServer().getPluginManager().registerEvents(this, this);
        PluginCommand cmd = getCommand("ipshield");
        if (cmd != null) cmd.setExecutor(this);
        getLogger().info("IPShield enabled - Protected by VDEV Studios");
    }

    @Override
    public void onDisable() {
        synchronized (this) { saveData(); }
    }

    // ---------- Core protection ----------

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        if (e.getLoginResult() != AsyncPlayerPreLoginEvent.Result.ALLOWED) return;

        String name = e.getName();
        String ip = e.getAddress().getHostAddress();
        String uuid = e.getUniqueId().toString();

        if (containsIgnoreCase(getConfig().getStringList("bypass-players"), name)) return;
        if (getConfig().getStringList("trusted-ips").contains(ip)) return;

        synchronized (this) {
            String path = "accounts." + uuid;
            String savedIp = data.getString(path + ".ip");
            long lastSeen = data.getLong(path + ".last-seen", 0L);
            long lockMs = getConfig().getLong("lock-minutes", 0L) * 60_000L;
            boolean expired = savedIp != null && lockMs > 0
                    && System.currentTimeMillis() - lastSeen > lockMs;

            if (savedIp == null || expired || savedIp.equals(ip)) {
                data.set(path + ".name", name);
                data.set(path + ".ip", ip);
                data.set(path + ".last-seen", System.currentTimeMillis());
                saveData();
                return;
            }

            // Different IP -> block
            int idNum = data.getInt("next-id", 1);
            data.set("next-id", idNum + 1);
            saveData();
            String id = String.format("%0" + Math.max(1, getConfig().getInt("id-digits", 4)) + "d", idNum);

            writeLog(id, name, ip, savedIp);

            List<String> lines = getConfig().getStringList("kick-message");
            String msg = color(String.join("\n", lines)
                    .replace("%id%", id).replace("%player%", name));
            e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, msg);

            if (getConfig().getBoolean("notify-staff", true)) {
                String staff = color(getConfig().getString("staff-message", "")
                        .replace("%id%", id).replace("%player%", name));
                Bukkit.getScheduler().runTask(this, () -> {
                    for (Player p : Bukkit.getOnlinePlayers())
                        if (p.hasPermission("ipshield.notify")) p.sendMessage(staff);
                });
            }
        }
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        synchronized (this) {
            String path = "accounts." + e.getPlayer().getUniqueId();
            if (data.contains(path)) {
                data.set(path + ".last-seen", System.currentTimeMillis());
                saveData();
            }
        }
    }

    // ---------- Commands ----------

    @Override
    public boolean onCommand(CommandSender s, Command c, String l, String[] a) {
        if (!s.hasPermission("ipshield.admin")) {
            s.sendMessage(color("&cNo permission."));
            return true;
        }
        if (a.length == 0) {
            s.sendMessage(color("&b/ipshield reload &7| &blogs [n] &7| &binfo <player> &7| &bunlock <player>"));
            return true;
        }
        switch (a[0].toLowerCase()) {
            case "reload" -> {
                reloadConfig();
                synchronized (this) { data = YamlConfiguration.loadConfiguration(dataFile); }
                s.sendMessage(color("&aIPShield reloaded."));
            }
            case "logs" -> {
                int n = 10;
                if (a.length > 1) try { n = Math.max(1, Math.min(50, Integer.parseInt(a[1]))); } catch (NumberFormatException ignored) {}
                try {
                    if (!logFile.exists()) { s.sendMessage(color("&7No logs yet.")); return true; }
                    List<String> all = Files.readAllLines(logFile.toPath(), StandardCharsets.UTF_8);
                    for (String line : all.subList(Math.max(0, all.size() - n), all.size()))
                        s.sendMessage(color("&7" + line));
                } catch (IOException ex) { s.sendMessage(color("&cCould not read logs.")); }
            }
            case "info" -> {
                if (a.length < 2) { s.sendMessage(color("&cUsage: /ipshield info <player>")); return true; }
                synchronized (this) {
                    String key = findAccount(a[1]);
                    if (key == null) { s.sendMessage(color("&cNo saved data for that player.")); return true; }
                    s.sendMessage(color("&bAccount: &f" + data.getString("accounts." + key + ".name")));
                    s.sendMessage(color("&bLocked IP: &f" + data.getString("accounts." + key + ".ip")));
                    long ls = data.getLong("accounts." + key + ".last-seen");
                    s.sendMessage(color("&bLast seen: &f" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(ls))));
                }
            }
            case "unlock" -> {
                if (a.length < 2) { s.sendMessage(color("&cUsage: /ipshield unlock <player>")); return true; }
                synchronized (this) {
                    String key = findAccount(a[1]);
                    if (key == null) { s.sendMessage(color("&cNo saved data for that player.")); return true; }
                    data.set("accounts." + key + ".ip", null);
                    saveData();
                }
                s.sendMessage(color("&aUnlocked. The next IP that joins as &f" + a[1] + " &awill become the new locked IP."));
            }
            default -> s.sendMessage(color("&cUnknown subcommand."));
        }
        return true;
    }

    // ---------- Helpers ----------

    private String findAccount(String name) {
        ConfigurationSection sec = data.getConfigurationSection("accounts");
        if (sec == null) return null;
        for (String key : sec.getKeys(false))
            if (name.equalsIgnoreCase(sec.getString(key + ".name"))) return key;
        return null;
    }

    private void writeLog(String id, String name, String attemptIp, String savedIp) {
        String line = "[" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + "] #" + id
                + " | account=" + name + " | attempt-ip=" + attemptIp + " | locked-ip=" + savedIp;
        getLogger().warning("Blocked: " + line);
        if (!getConfig().getBoolean("log-to-file", true)) return;
        try {
            getDataFolder().mkdirs();
            Files.writeString(logFile.toPath(), line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) { getLogger().warning("Could not write log: " + ex.getMessage()); }
    }

    private void saveData() {
        try { data.save(dataFile); } catch (IOException ex) { getLogger().warning("Could not save data.yml: " + ex.getMessage()); }
    }

    private static boolean containsIgnoreCase(List<String> list, String s) {
        for (String x : list) if (x.equalsIgnoreCase(s)) return true;
        return false;
    }

    private static String color(String s) { return ChatColor.translateAlternateColorCodes('&', s); }
}
