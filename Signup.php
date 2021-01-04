<?php
 include 'config.php';
// Define variables and initialize with empty values
$Email = $password = $confirm_password = $employee_id = $first_name = $last_name = "";
$Email_err = $password_err = $confirm_password_err = $first_name_err = $last_name_err = $employee_id_err ="";

// Processing form data when form is submitted
if($_SERVER["REQUEST_METHOD"] == "POST"){

    // Validate Email
    if(empty(trim($_POST["Email"]))){
        $Email_err = "Please enter a email.";
    } else{
        // Prepare a select statement
        $sql = "SELECT Email FROM users WHERE Email = ?";
        
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "s", $param_Email);
            
            // Set parameters
            $param_Email = trim($_POST["Email"]);
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                /* store result */
                mysqli_stmt_store_result($stmt);
                
                if(mysqli_stmt_num_rows($stmt) == 1){
                    $Email_err = "This Email is already taken.";
                } else{
                    $Email = trim($_POST["Email"]);
                }
            } else{
                echo "Oops! Something went wrong. Please try again later.";
            }
        }
        
             // Close statement
        mysqli_stmt_close($stmt);   
    }

    //Validate Employee ID
    if(empty(trim($_POST["Employee_ID"])))
    {
        $employee_id_err = "Please enter employee id";
    } elseif(!(preg_match("/^[1-9][0-9]*$/",$_POST["Employee_ID"])) || is_int($_POST["Employee_ID"])) {
        $employee_id_err = "Please enter valid employee id";
    } else {
        $employee_id = trim($_POST["Employee_ID"]);
    }
    //Validate First name
    if(empty(trim($_POST["First_Name"])))
    {
        $first_name_err = "Please enter first name.";
    } elseif(!(preg_match("/^([a-zA-Z' ]+)$/",$_POST["First_Name"]))) {
        $first_name_err = "Please enter valid first name";
    } else {
        $first_name = trim($_POST["First_Name"]);
    }

    //Validate Last name
    if(empty(trim($_POST["Last_Name"])))
    {
        $last_name_err = "Please enter last name.";
    } elseif(!(preg_match("/^([a-zA-Z' ]+)$/",$_POST["Last_Name"]))) {
        $last_name_err = "Please enter valid last name";
    } else {
        $last_name = trim($_POST["Last_Name"]);
    }

    // Validate password
    if(empty(trim($_POST["password"]))){
        $password_err = "Please enter password.";     
    } elseif(strlen(trim($_POST["password"])) < 6){
        $password_err = "Password must have atleast 6 characters.";
    } else{
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password
    if(empty(trim($_POST["confirm_password"]))){
        $confirm_password_err = "Please confirm password.";     
    } else{
        $confirm_password = trim($_POST["confirm_password"]);
        if(empty($password_err) && ($password != $confirm_password)){
            $confirm_password_err = "Password did not match.";
        }
    }
    
    // Check input errors before inserting in database
    if(empty($employee_id_err) && empty($first_name_err) && empty($last_name_err) && empty($Email_err) && empty($password_err) && empty($confirm_password_err)){
        
        // Prepare an insert statement
        $sql = "INSERT INTO Users (First_Name, Last_Name, Emp_ID, Email, Password) VALUES (?, ?, ?, ?, ?)";
         
        if($stmt = mysqli_prepare($link, $sql)){
            // Bind variables to the prepared statement as parameters
            mysqli_stmt_bind_param($stmt, "ssiss", $param_FirstName, $param_LastName, $param_EmpID, $param_Email, $param_password);
            
            // Set parameters
            $param_FirstName = $first_name;
            $param_LastName = $last_name;
            $param_EmpID = $employee_id;
            $param_Email = $Email;
            $param_password = password_hash($password, PASSWORD_DEFAULT); // Creates a password hash
            
            // Attempt to execute the prepared statement
            if(mysqli_stmt_execute($stmt)){
                echo '<script>alert("Account created successfully")</script>'; 
                // Redirect to login page
			    //header("location: login.php");
            } else{
                echo "Something went wrong. Please try again later.";
            }
        }
         
        // Close statement
        mysqli_stmt_close($stmt);
    }
    // Close connection
    mysqli_close($link);
}
?>
 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Sign Up</title>
    <link rel="icon" href="images/signup.png" type="image/x-icon">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
    <style type="text/css">
        body{ font: 14px sans-serif; }
        .wrapper{ width: 350px; padding: 20px; }
    </style>
</head>
<body>
    <div class="wrapper">
        <h2>Sign Up</h2>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <div class="form-group <?php echo (!empty($employee_id_err)) ? 'has-error' : ''; ?>">
                <label>Employee ID</label>
                <input type="number" name="Employee_ID" class="form-control" min="1" value="<?php echo $employee_id; ?>" >
                <span class="help-block"><?php echo $employee_id_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($first_name_err)) ? 'has-error' : ''; ?>">
                <label>First Name</label>
                <input type="text" name="First_Name" class="form-control" value="<?php echo $first_name; ?>">
                <span class="help-block"><?php echo $first_name_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($last_name_err)) ? 'has-error' : ''; ?>">
                <label>Last Name</label>
                <input type="text" name="Last_Name" class="form-control" value="<?php echo $last_name; ?>">
                <span class="help-block"><?php echo $last_name_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($Email_err)) ? 'has-error' : ''; ?>">
                <label>Email</label>
                <input type="email" name="Email" class="form-control" value="<?php echo $Email; ?>">
                <span class="help-block"><?php echo $Email_err; ?></span>
            </div>    
            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                <label>Password</label>
                <input type="password" name="password" class="form-control" value="<?php echo $password; ?>">
                <span class="help-block"><?php echo $password_err; ?></span>
            </div>
            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                <label>Confirm Password</label>
                <input type="password" name="confirm_password" class="form-control" value="<?php echo $confirm_password; ?>">
                <span class="help-block"><?php echo $confirm_password_err; ?></span>
            </div>
            <div class="form-group">
                <input type="submit" class="btn btn-primary" value="Submit">
                <input type="reset" class="btn btn-default" value="Reset">
            </div>
            <p>Already have an account? <a href="login.php">Login here</a>.</p>
        </form>
    </div>    
</body>
</html>
