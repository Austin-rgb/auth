package ochie.auth;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Random;
import ochie.auth.Auth0;

public class Auth0 {
  int verWidth = 10;
  int verLength = 6;
  int sesWidth = 75;
  int sesLength = 48;
  Statement statement = null;
  boolean allowMultipleSessions = false;
  boolean allowUnverifiedUsernames = true;

  Auth0(Statement statement) {
    this.statement = statement;
    initialize();
  }

  void initialize() {
    try {
      statement.execute(
          "create table if not exists auth_credentials(username string, password string)");
      statement.execute(
          "create table if not exists auth_sessions(sessionId string primary key, username string,  timestamp string,  extras string)");
      statement.execute(
          " create table if not exists auth_logs(timestamp string primary key,  sessionId string, data string)");
      statement.execute(
          "create table if not exists auth_pending_verifications(username string primary key, code string)");
      statement.execute(
          "create table if not exists auth_pending_registrations(username string, password string)");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  String hasher(String input) {
    String output = null;
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-384");
      byte[] o = md.digest(input.getBytes());
      output = new BigInteger(o).toString(32);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return output;
  }

  String getSessionId() {
    Random r = new Random();
    char[] result = new char[sesLength];
    for (int i = 0; i < sesLength; i++) {
      int myr = -1;
      while (myr < 0 || (myr >= 10 && myr < 17) || (myr >= 43 && myr < 50)) {
        myr = r.nextInt(sesWidth);
      }
      result[i] = (char) new Integer(myr + 48).byteValue();
    }
    return new String(result);
  }

  String getVerificationCode() {
    Random r = new Random();
    char[] result = new char[verLength];
    for (int i = 0; i < verLength; i++) {
      int myr = -1;
      while (myr < 0 || (myr >= 10 && myr < 17) || (myr >= 43 && myr < 50)) {
        myr = r.nextInt(verWidth);
      }
      result[i] = (char) new Integer(myr + 48).byteValue();
    }
    return new String(result);
  }

  public Auth0 setVerificationCodeSize(int width, int length) {
    verWidth = width;
    verLength = length;
    return this;
  }

  public Auth0 setSessionIdSize(int width, int length) {
    sesWidth = width;
    sesLength = length;
    return this;
  }

  public Auth0 setAllowMultipleSessions(boolean allowMultipleSessions) {
    this.allowMultipleSessions = allowMultipleSessions;
    return this;
  }

  public Auth0 setAllowUnverifiedUsernames(boolean allowUnverifiedUsernames) {
    this.allowUnverifiedUsernames = allowUnverifiedUsernames;
    return this;
  }

  public ArrayList<Log> getLogs(String username) {
    ArrayList<Log> result = new ArrayList<>();
    try {
      ResultSet rs = statement.executeQuery("select * auth_sessions where \"" + username + "\"");
      String[] sessions = new String[rs.getFetchSize()];
      int i = 0;
      while (rs.next()) {
        sessions[i] = rs.getString("sessionId");
        i++;
      }
      for (String session : sessions) {
        ResultSet rs1 =
            statement.executeQuery("select * from auth_logs where sessionId=\"" + session + "\"");
        while (rs1.next()) {
          Log log = new Log(rs.getString("timestamp"), rs.getString("data"));
          result.add(log);
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return result;
  }

  public String login(String username, String password) throws PasswordMismatch {
    try {
      ResultSet rs =
          statement.executeQuery(
              "select * from auth_credentials where username = \""
                  + username
                  + "\",\""
                  + hasher(password)
                  + "\")");
      if (rs.getFetchSize() > 0) {
        String sessionId = getSessionId();
        statement.executeUpdate(
            "insert into auth_sessions values(\"" + sessionId + "\",\"" + username + "\")");
        return sessionId;
      }
    } catch (Exception e) {
      e.printStackTrace();
    }

    throw new PasswordMismatch();
  }

  public boolean register(String username, String password) {
    try {
      if (allowUnverifiedUsernames) {
        statement.executeUpdate(
            "insert into auth_credentials values(\""
                + username
                + "\",\""
                + hasher(password)
                + "\")");
      } else {
        statement.executeUpdate(
            "insert into auth_pending_registrations values(\""
                + username
                + "\",\""
                + hasher(password)
                + "\")");
      }
      return true;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public String verify(String username) {
    String code = getVerificationCode();
    try {
      statement.executeUpdate(
          "insert into auth_pending_verifications values(\"" + username + "\",\"" + code + "\")");
      return code;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public boolean verify(String username, String code) {
    try {
      statement.executeUpdate(
          "delete from auth_pending_verifications where username=\"" + username + "\"");
      statement.executeUpdate(
          " insert  into  auth_credentials select * from auth_pending_registrations where username=\""
              + username
              + "\"");
      statement.executeUpdate(
          "delete from auth_pending_registrations where username=\"" + username + "\"");
      return true;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return false;
  }

  public Session getSession(String sessionId) throws InvalidSession {
    return new Session(sessionId);
  }

  public String[] getSessions(String username) {
    try {
      ResultSet rs =
          statement.executeQuery(
              "select * from auth_sessions where username=\"" + username + "\",\"");
      int size = rs.getFetchSize();
      String[] sessions = new String[size];
      int i = 0;
      while (rs.next()) {
        sessions[i] = rs.getString("sessionId");
        i++;
      }
      return sessions;
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  class Session {
    String sessionId = "";

    Session(String sessionId) throws InvalidSession {
      try {
        ResultSet rs =
            statement.executeQuery("select * auth_sessions where sessionId=\"" + sessionId + "\"");
        if (rs.getFetchSize() < 1) throw new InvalidSession();
        else this.sessionId = sessionId;
      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    public boolean log(String data) {
      try {
        statement.executeUpdate(
            "insert into auth_log values(\""
                + LocalDateTime.now()
                + "\",\""
                + sessionId
                + "\",\""
                + data
                + "\")");
      } catch (Exception e) {
        e.printStackTrace();
      }
      return false;
    }

    public String getEmail() {
      try {
        ResultSet rs = statement.executeQuery("");
        return rs.getString("email");
      } catch (Exception e) {
        e.printStackTrace();
      }
      return null;
    }
  }

  class Log {
    LocalDateTime timestamp;
    String description;

    Log(String timestamp, String data) {
      this.timestamp = LocalDateTime.parse(timestamp);
      description = data;
    }
  }

  class InvalidSession extends Exception {
    static final long serialVersionUID = 1001;

    InvalidSession() {
      super("Invalid session id");
    }
  }

  class PasswordMismatch extends Exception {
    static final long serialVersionUID = 1002;

    PasswordMismatch() {
      super("Password mismatch");
    }
  }
}
