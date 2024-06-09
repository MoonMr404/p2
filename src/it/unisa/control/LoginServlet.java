package it.unisa.control;
import java.io.IOException;
import java.security.MessageDigest;
import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import it.unisa.model.*;

@WebServlet("/Login")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request, response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        UserDao userDao = new UserDao();

        try {
            String rawUsername = request.getParameter("un");
            String rawPassword = request.getParameter("pw");

            // Sanitize the inputs to prevent XSS
            String username = sanitizeInput(rawUsername);
            String password = sanitizeInput(rawPassword);

            // Hashing della password
            String hashedPassword = hashPassword(password);

            UserBean user = userDao.doRetrieve(username, hashedPassword);

            String checkout = request.getParameter("checkout");

            if (user != null && user.isValid()) {
                HttpSession session = request.getSession(true);
                session.setAttribute("currentSessionUser", user);
                if (checkout != null) {
                    response.sendRedirect(request.getContextPath() + "/account?page=Checkout.jsp");
                } else {
                    response.sendRedirect(request.getContextPath() + "/Home.jsp");
                }
            } else {
                response.sendRedirect(request.getContextPath() + "/Login.jsp?action=error"); // Pagina di errore
            }
        } catch (SQLException e) {
            System.out.println("Database Error: " + e.getMessage());
            response.sendRedirect(request.getContextPath() + "/Login.jsp?action=db_error"); // Pagina di errore del database
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            response.sendRedirect(request.getContextPath() + "/Login.jsp?action=error"); // Pagina di errore generico
        }
    }

    // Metodo per l'hashing della password (SHA-512)
    private String hashPassword(String password) throws Exception {
        // Implementazione dell'hashing della password (SHA-512)
        // Qui potresti utilizzare la tua implementazione di hashing, come abbiamo fatto nella servlet di registrazione
        // Per semplicità, useremo SHA-512 in questo esempio
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        byte[] hashedBytes = digest.digest(password.getBytes());

        // Converti l'array di byte in una stringa esadecimale
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : hashedBytes) {
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    }

    // Metodo per sanificare l'input
    private String sanitizeInput(String input) {
        if (input != null) {
            // Replace <, >, &, ", ' with their HTML encoded equivalents
            input = input.replaceAll("&", "&amp;");
            input = input.replaceAll("<", "&lt;");
            input = input.replaceAll(">", "&gt;");
            input = input.replaceAll("\"", "&quot;");
            input = input.replaceAll("'", "&#39;");
        }
        return input;
    }
}
