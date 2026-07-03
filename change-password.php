<?php
session_start();
$_SESSION['Message']="";
?>

<?php
include("dbstring.php");
include("audit_notifications.php");
include_once("user-management-utils.php");
ensure_user_management_columns($con);
@$_ForceReset=(isset($_GET['force']) && $_GET['force']=="1");

$_CurrentUsername = isset($_SESSION['USERNAME']) ? trim((string)$_SESSION['USERNAME']) : "";
if($_CurrentUsername === "" && isset($_SESSION['USERID']) && trim((string)$_SESSION['USERID']) !== ""){
    $stmtCurrentUser = @mysqli_prepare($con, "SELECT username FROM tblsystemuser WHERE userid=? LIMIT 1");
    if($stmtCurrentUser){
        mysqli_stmt_bind_param($stmtCurrentUser, "s", $_SESSION['USERID']);
        mysqli_stmt_execute($stmtCurrentUser);
        $currentUserResult = mysqli_stmt_get_result($stmtCurrentUser);
        if($currentUserResult && ($currentUserRow = mysqli_fetch_array($currentUserResult, MYSQLI_ASSOC))){
            $_CurrentUsername = trim((string)$currentUserRow['username']);
            $_SESSION['USERNAME'] = $_CurrentUsername;
        }
        mysqli_stmt_close($stmtCurrentUser);
    }
}

$_PostedUsername = isset($_POST['username']) ? trim((string)$_POST['username']) : $_CurrentUsername;

if(isset($_POST['update_account'])){
    $_OldpasswordRaw = isset($_POST['oldpassword']) ? (string)$_POST['oldpassword'] : "";
    $_NewUsername = $_PostedUsername;
    $_NewpasswordRaw = isset($_POST['newpassword']) ? (string)$_POST['newpassword'] : "";
    $_RepeatPasswordRaw = isset($_POST['repeatpassword']) ? (string)$_POST['repeatpassword'] : "";
    $_Oldpassword = md5($_OldpasswordRaw);
    $_Newpassword = md5($_NewpasswordRaw);

    if($_NewUsername === ""){
        $_SESSION['Message'] = "<div style='color:red'>Please enter a new username.</div>";
    }
    elseif($_NewpasswordRaw === ""){
        $_SESSION['Message'] = "<div style='color:red'>Please enter a new password.</div>";
    }
    elseif($_NewpasswordRaw !== $_RepeatPasswordRaw){
        $_SESSION['Message'] = "<div style='color:red'>The repeated password does not match the new password.</div>";
    }
    else{
        $_DuplicateUsername = false;
        $stmtCheckUsername = @mysqli_prepare($con, "SELECT userid FROM tblsystemuser WHERE username=? AND userid<>? LIMIT 1");
        if($stmtCheckUsername){
            mysqli_stmt_bind_param($stmtCheckUsername, "ss", $_NewUsername, $_SESSION['USERID']);
            mysqli_stmt_execute($stmtCheckUsername);
            $dupResult = mysqli_stmt_get_result($stmtCheckUsername);
            $_DuplicateUsername = ($dupResult && mysqli_num_rows($dupResult) > 0);
            mysqli_stmt_close($stmtCheckUsername);
        }

        if($_DuplicateUsername){
            $_SESSION['Message'] = "<div style='color:red'>That username is already used by another account.</div>";
        }
        else{
            $stmtUpdate = @mysqli_prepare($con, "UPDATE tblsystemuser
                SET username=?,password=?,password_reset_required=0,password_last_reset_at=NOW()
                WHERE userid=? AND password=?
                LIMIT 1");
            if($stmtUpdate){
                mysqli_stmt_bind_param($stmtUpdate, "ssss", $_NewUsername, $_Newpassword, $_SESSION['USERID'], $_Oldpassword);
                $saved = mysqli_stmt_execute($stmtUpdate);
                $affected = mysqli_stmt_affected_rows($stmtUpdate);
                $stmtError = mysqli_stmt_error($stmtUpdate);
                mysqli_stmt_close($stmtUpdate);

                if($saved && $affected > 0){
                    $_SESSION['USERNAME'] = $_NewUsername;
                    $_CurrentUsername = $_NewUsername;
                    $_PostedUsername = $_NewUsername;
                    logSystemChange(
                        $con,
                        "PASSWORD_CHANGE",
                        "Password was changed by ".$_SESSION['SYSTEMTYPE']." user."
                    );
                    $_SESSION['Message'] = "<div style='color:green;text-align:center;background-color:white'>Account Successfully Updated<br/><br/><a href='index.php' style='color:blue'>Login</a><br/><br/></div>";
                }
                elseif($saved){
                    $_SESSION['Message'] = "<div style='color:red'>Your current password is incorrect, so the account was not updated.</div>";
                }
                else{
                    $_SESSION['Message'] = "<div style='color:red'>Account failed to update,".$stmtError."</div>";
                }
            }
            else{
                $_SESSION['Message'] = "<div style='color:red'>Account failed to update right now. Please try again.</div>";
            }
        }
    }
}
?>

<html>
<head>
<?php
include("links.php");
?>
<link rel="stylesheet" href="css/change-password.css">

</head>

<body>

	<div class="header">
		<!--<img src="images/logo.png" width="100px" height="100px" alt="logo"/>-->
	<?php
	include("menu.php");
	?>		
	</div>

<div class="main-platform password-page">
	<section class="password-hero">
		<div>
			<span class="password-kicker">Account Security</span>
			<h1>Change Password</h1>
			<p>Update your login details to keep your account secure.</p>
		</div>
		<div class="password-hero-card">
			<i class="fa fa-lock"></i>
			<span>Secure Account</span>
		</div>
	</section>

	<div class="password-shell">
		<section class="password-panel">
			<div class="password-panel-heading">
				<span class="password-icon"><i class="fa fa-shield"></i></span>
				<div>
					<h2>Update Account</h2>
					<p>Enter your current password, then choose a new username and password.</p>
				</div>
			</div>
	<?php
	echo $_SESSION['Message'];
	?>
<?php
if($_ForceReset){
    echo "<div class='password-alert'><i class='fa fa-exclamation-triangle'></i> Your password was reset by an administrator. Please choose a new username and password before continuing.</div>";
}
?>
	
			<form method="post" id="formID" name="formID" action="change-password.php<?php echo $_ForceReset ? '?force=1' : ''; ?>">

			<label>User Id</label>
			<input type="text" id="userid" name="userid" value="<?php echo $_SESSION['USERID'];?>" class="validate[required]" readonly/>

			<label>Old Password</label>
			<input type="password" id="oldpassword" name="oldpassword" value="" class="validate[required]" placeholder="Type Old Password"/>

			<label>New Username</label>
			<input type="text" id="username" name="username" value="<?php echo htmlspecialchars($_PostedUsername, ENT_QUOTES, 'UTF-8'); ?>" placeholder="Type New Username" class="validate[required]" />

			<label>New Password</label>
			<input type="password" id="newpassword" name="newpassword" value="" class="validate[required]" placeholder="Type New Password"/>

			<label>Repeat Password</label>
			<input type="password" id="repeatpassword" name="repeatpassword" value="" class="validate[required,equals[newpassword]]" placeholder="Repeat Password"/><br/><br/>
			<div class="password-actions"><button class="button-edit password-btn password-btn-primary" id="update_account" name="update_account"><i class="fa fa-edit"></i> Update Account</button></div>
		</form>
		</section>
	</div>
</div>
</body>
</html>
