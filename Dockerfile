How do i incorporate PyOTP for email / QR code into this?

I also happen to preload some accounts, so if i put the QR code for google authenticator directly after register, my pre-loaded acc wont have a chance to even generate a QR code, so i was thinking of putting into a separate tab, sort of like a profile page for them to revisit anytime

            user = User(**row)
            login_user(user)
            log_action(user.id, f"{user.role} '{user.username}' logged in.")