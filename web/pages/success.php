<?php 

if (!isset($_SESSION['token'])) 
{
    header("Location: ?page=main");
    exit();
}

?>

<div class="container">
    <div class="wrapper">
        <h3>Pandore</h3>
        <p>Welcome, <?php echo $_SESSION['user_info']['username']; ?> !</p>
        <p>Below you will find your account token, don't lose it, it's impossible to recover !</p>
        <p>Account Token : <?php echo $_SESSION['token']; ?></p>
        <form method="post"> 
        <div class="row button">
            <input type="button" id="copyButton" value="Copy" style="margin-right: 10px;">     
            <input type="button" value="Exit" onclick="window.location.href='?page=main';">
        </div>
        </form>
    </div>
</div>
    <script>
        document.getElementById("copyButton").addEventListener("click", function() {
            var accountID = "<?php echo $_SESSION['token']; ?>";
            var tempInput = document.createElement("input");
            tempInput.value = accountID;
            document.body.appendChild(tempInput);
            tempInput.select();
            document.execCommand("copy");
            document.body.removeChild(tempInput);
        });
    </script>
</body>
</html>