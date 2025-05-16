<?php
// Email Test Script
require 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Create log file for debugging
$logFile = 'email_test_debug.log';
file_put_contents($logFile, date('Y-m-d H:i:s') . ": Starting email test\n", FILE_APPEND);

try {
    // Create a new PHPMailer instance
    $mail = new PHPMailer(true);
    
    // Server settings
    $mail->SMTPDebug = 2; // Enable verbose debug output
    $mail->Debugoutput = function($str, $level) use ($logFile) {
        file_put_contents($logFile, date('Y-m-d H:i:s') . ": $str\n", FILE_APPEND);
    };
    
    $mail->isSMTP();                                      
    $mail->Host       = 'smtp.gmail.com';                 
    $mail->SMTPAuth   = true;                             
    $mail->Username   = 'rotiseribakeryemail@gmail.com';  
    $mail->Password   = 'jlxf jvxl ezhn txum';           
    $mail->SMTPSecure = 'tls'; // Use string instead of PHPMailer constant
    $mail->Port       = 587;                             

    // Recipients
    $mail->setFrom('rotiseribakeryemail@gmail.com', 'Roti Seri Bakery');
    $mail->addAddress('rotiseribakeryemail@gmail.com'); // Add a recipient (testing with the same email)

    // Content
    $mail->isHTML(true);
    $mail->Subject = 'Email Test ' . date('Y-m-d H:i:s');
    $mail->Body    = 'This is a test email from the RotiSeri Bakery system to verify that email sending is working correctly.<br><br>Sent at: ' . date('Y-m-d H:i:s');
    $mail->AltBody = 'This is a test email from the RotiSeri Bakery system. Sent at: ' . date('Y-m-d H:i:s');

    // Send email
    $mail->send();
    echo "Message has been sent successfully!";
    file_put_contents($logFile, date('Y-m-d H:i:s') . ": Email sent successfully\n", FILE_APPEND);
    
} catch (Exception $e) {
    echo "Message could not be sent. Mailer Error: {$mail->ErrorInfo}";
    file_put_contents($logFile, date('Y-m-d H:i:s') . ": Email sending failed - Error: " . $mail->ErrorInfo . "\n", FILE_APPEND);
}
?>