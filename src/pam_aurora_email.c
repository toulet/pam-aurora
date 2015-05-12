/**
 * file:        pam_aurora_email.c
 * description: Aurora emails PAM module sources
 * authors:     Cyrille TOULET <cyrille.toulet@linux.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <libconfig.h>
#include <curl/curl.h>
#include <uuid/uuid.h>


/**
 * PAM service function to alter credentials
 * @param pam_handle The PAM handle
 * @param pam_flags The PAM authentication flags
 * @param pam_argc The PAM arguments count
 * @param pam_argv The PAM arguments array
 * @return A PAM return code
 * @see man 3 pam_sm_setcred
 */
PAM_EXTERN int 
pam_sm_setcred(pam_handle_t *pam_handle, int pam_flags, int pam_argc, 
const char **pam_argv)
{
    /* The user credential was successfully set */
    return PAM_SUCCESS;
}


/**
 * PAM service function for account management
 * @param pam_handle The PAM handle
 * @param pam_flags The PAM authentication flags
 * @param pam_argc The PAM arguments count
 * @param pam_argv The PAM arguments array
 * @return A PAM return code
 * @see man 3 pam_sm_acct_mgmt
 */
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pam_handle, int pam_flags, int pam_argc, 
const char **pam_argv)
{
    /* The authentication token was successfully updated */
    return PAM_AUTH_ERR;
}


/**
 * This function lets us do IO via PAM
 * @param pam_handle The PAM handle
 * @param pam_argc The number of args
 * @param pam_message The message to prompt
 * @param pam_response The user response
 * @return A PAM return code
 * @see pam_unix/support.c
 */
int
pam_converse(pam_handle_t *pam_handle, int pam_argc, 
struct pam_message **pam_message, struct pam_response **pam_response)
{
    /* PAM data */
    struct pam_conv *pam_conversation;
    int pam_status;

    /* Check feasibility of PAM conversations */
    pam_status = pam_get_item(pam_handle, PAM_CONV, 
        (const void **) &pam_conversation);

    /* Converse with PAM */
    if(pam_status == PAM_SUCCESS)
        pam_status = pam_conversation->conv(pam_argc, 
            (const struct pam_message **) pam_message, pam_response, 
            pam_conversation->appdata_ptr);

    /* Return PAM status */
    return pam_status;
}


/**
 * This function looks for user data in directory
 * @param pam_handle The PAM handle
 * @param pam_user_login The user login
 * @param pam_user_email The email destination
 * @return A PAM return code
 */
int
pam_directory_lookup(pam_handle_t *pam_handle, const char *pam_user_login, 
char *pam_user_email)
{
    /* The module dialogs */
    struct pam_message *pam_dialog_message[1];
    struct pam_message pam_dialog_message_ptr[1];
    struct pam_response *pam_dialog_response;

    /* The module directory */
    config_t pam_directory;
    FILE *pam_directory_fd;
    config_setting_t *pam_directory_emails;

    /* The email buffer */
    const char *stored_user_email;

    /* Init PAM dialog variables */
    pam_dialog_message[0] = &pam_dialog_message_ptr[0];
    pam_dialog_response = NULL;

    /* Init configuration */
    config_init(&pam_directory);

    /* Init configuration file stream */
    if((pam_directory_fd = fopen("/etc/aurora/directory.conf", "r")) == NULL)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to open directory";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the directory */
        config_destroy(&pam_directory);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Read and parse the configuration file */
    if(config_read(&pam_directory, pam_directory_fd) == CONFIG_FALSE)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to read directory";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the directory */
        config_destroy(&pam_directory);

        /* Properly destroy the directory file stream */
        fclose(pam_directory_fd);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Get the emails collection */
    pam_directory_emails = config_lookup(&pam_directory, "emails");

    /* Look for user email */
    if (config_setting_lookup_string(pam_directory_emails, 
        pam_user_login, &stored_user_email) == CONFIG_FALSE)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Email not found in directory";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the directory */
        config_destroy(&pam_directory);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Check the email address length */
    if(strlen(stored_user_email) > 320)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Email address too long (max 320 chars)";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the directory */
        config_destroy(&pam_directory);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Copy email */
    strcpy(pam_user_email, stored_user_email);

    /* Properly destroy the directory */
    config_destroy(&pam_directory);

    /* User email found */
    return PAM_SUCCESS;
}


/**
 * The email context structure for curl library 
 **/
struct pam_email_ctx
{
    /* Email transmitter */
    char *from;
  
    /* Email receiver */
    char *to;

    /* Receiver username */
    char *user;

    /* Authentication code */
    char *code;
  
    /* Email id */
    char *uuid;
  
    /* Current line of message */
    int current_line;
};


/**
 * Email payload function for curl library
 * @param buffer The data buffer
 * @param size The size to read
 * @param items_count The items count to read
 * @param email_ctx The email context
 * @return The data size
 */
size_t
pam_payload_email_source(char *buffer, size_t size, size_t items_count, 
void *email_ctx)
{
    /* The email context */
    struct pam_email_ctx *ctx = (struct pam_email_ctx *) email_ctx;

    /* The message line with length */
    char *line;
    size_t line_length;
    
   
    /* If the message has been read, exit from here */
    if((size == 0) || (items_count == 0) || ((size * items_count) < 1))
        return 0;

    /* Build current line */
    switch(ctx->current_line)
    {
        case 0:
	    /* Line 0: Date */
	    line = (char*) malloc(40 * sizeof(char));
            sprintf(line, "Date: Mon, 29 Nov 2010 21:54:29 +1100\r\n");
            break;

        case 1:
	    /* Line 1: To */
            line = (char*) malloc((strlen(ctx->to) + 7) * sizeof(char));
            sprintf(line, "To: %s\r\n", (char*) ctx->to);
            break;

        case 2:
	    /* Line 2: From */
            line = (char*) malloc((strlen(ctx->from) + 22) * sizeof(char));
            sprintf(line, "From: %s (PAM Aurora)\r\n", (char*) ctx->from);
            break;

        case 3:
            /* Line 3: ID */
            line = (char*) malloc((strlen(ctx->uuid) + 15) * sizeof(char));
            sprintf(line, "Message-ID: %s\r\n", (char*) ctx->uuid);
            break;

        case 4:
	    /* Line 2: Subject */
            line = (char*) malloc(32 * sizeof(char));
            sprintf(line, "Subject: Your validation code\r\n");
            break;

        case 5:
	    /* Line 2: Jump */
            line = (char*) malloc(3 * sizeof(char));
            sprintf(line, "\r\n");
            break;

        case 6:
	    /* Line 6: Message (line 1) */
	  line = (char*) malloc((7 + strlen(ctx->user))  * sizeof(char));
            sprintf(line, "Hi %s,\r\n", ctx->user);
	    break;

        case 7:
	    /* Line 2: Message (line 2) */
            line = (char*) malloc(3 * sizeof(char));
            sprintf(line, "\r\n");
            break;

        case 8:
	    /* Line 6: Message (line 3) */
            line = (char*) malloc((32 + strlen(ctx->code)) * sizeof(char));
            sprintf(line, "Your authentication code is %s.\r\n", ctx->code);
	    break;
	    
        default:
            /* Line out of range  */
            return 0;
            break;
    }

    /* Get line length */
    line_length = strlen(line);

    /* Fill buffer */
    memcpy(buffer, line, line_length);

    /* Increase line */
    ctx->current_line++;

    /* Return length */
    return line_length;
}


/**
 * This function transmits the code to the user
 * @param pam_user The user login
 * @param pam_email The user email address
 * @param pam_code The generated code
 * @return A PAM return code
 */
int
pam_transmit_code(pam_handle_t *pam_handle, const char *pam_user,
const char *pam_email, const char *pam_code)
{
    /* The curl instance */
    CURL *curl;

    /* The curl return */
    CURLcode res = CURLE_OK;

    /* The recipents list */
    struct curl_slist *recipients = NULL;

    /* The email contect */
    struct pam_email_ctx email_ctx;
    
    /* The email id */
    uuid_t uuid;
    char email_id[37];

    /* The mail server configuration */
    const char *pam_mail_server_host;
    const char *pam_mail_server_user;
    const char *pam_mail_server_pass;

    /* The module configuration */
    config_t pam_config;
    FILE *pam_config_fd;

    /* The module dialogs */
    struct pam_message *pam_dialog_message[1];
    struct pam_message pam_dialog_message_ptr[1];
    struct pam_response *pam_dialog_response;

    /* Init PAM dialog variables */
    pam_dialog_message[0] = &pam_dialog_message_ptr[0];
    pam_dialog_response = NULL;

    /* Generate a random id for email */
    uuid_generate_random(uuid);

    /* Init configuration */
    config_init(&pam_config);

    /* Init configuration file stream */
    if((pam_config_fd = fopen("/etc/aurora/email.conf", "r")) == NULL)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to open configuration";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the configuration */
        config_destroy(&pam_config);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Read and parse the configuration file */
    if(config_read(&pam_config, pam_config_fd) == CONFIG_FALSE)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to read configuration";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the configuration */
        config_destroy(&pam_config);

        /* Properly destroy the configuration file stream */
        fclose(pam_config_fd);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Get mail server settings */
    if(
        (config_lookup_string(&pam_config, "mail_server_host", 
            &pam_mail_server_host) == CONFIG_FALSE) ||
        (config_lookup_string(&pam_config, "mail_server_user", 
            &pam_mail_server_user) == CONFIG_FALSE) ||
        (config_lookup_string(&pam_config, "mail_server_pass", 
            &pam_mail_server_pass) == CONFIG_FALSE)
    )
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Mail server configuration not found";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the directory */
        config_destroy(&pam_config);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Set email context */
    email_ctx.from = (char*) pam_mail_server_user;
    email_ctx.to = (char*) pam_email;
    email_ctx.user = (char*) pam_user;
    email_ctx.code = (char*) pam_code;
    uuid_unparse(uuid, email_id);
    email_ctx.uuid = email_id;
    email_ctx.current_line = 0;
    
    /* Init curl */
    curl = curl_easy_init();

    if(curl) {
	/* Set server url */
        curl_easy_setopt(curl, CURLOPT_URL, (char*) pam_mail_server_host);

	/* Set username */
        curl_easy_setopt(curl, CURLOPT_USERNAME, (char*) pam_mail_server_user);

	/* Set password */
        curl_easy_setopt(curl, CURLOPT_PASSWORD, (char*) pam_mail_server_pass);

	/* Enable SSL */
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);

	/* Set sender */
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, (void *) email_ctx.from);

	/* Set secipients */
        recipients = curl_slist_append(recipients, (void *) email_ctx.to);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

	/* Register the payload function */
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, pam_payload_email_source);

	/* Set the email context */
        curl_easy_setopt(curl, CURLOPT_READDATA, &email_ctx);

	/* Enable upload */
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	/* Send email */
        res = curl_easy_perform(curl);

        if(res != CURLE_OK)
	{
            /* An error occurs */
            pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
            pam_dialog_message_ptr[0].msg = 
                "[ERROR] Email transmission failure";
            pam_converse(pam_handle, 1, pam_dialog_message, 
                &pam_dialog_response);


            /* Free memory */
            config_destroy(&pam_config);
            curl_slist_free_all(recipients);
            curl_easy_cleanup(curl);

	    /* Reject authentication */
            return PAM_AUTH_ERR;
	}

	/* Free memory */
        config_destroy(&pam_config);
        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }
  
    /* Transmission success */
    return PAM_SUCCESS;
}


/**
 * This function performs the task of authenticating the user
 * @param pam_handle The PAM handle
 * @param pam_flags The authentication flags
 * @param pam_argc The system arguments count
 * @param pam_argv The system arguments array
 * @return A PAM return code
 */
PAM_EXTERN int 
pam_sm_authenticate(pam_handle_t *pam_handle, int pam_flags, int pam_argc, 
const char **pam_argv)
{
    /* The module dialogs */
    struct pam_message *pam_dialog_message[1];
    struct pam_message pam_dialog_message_ptr[1];
    struct pam_response *pam_dialog_response;
    char *pam_dialog_input;

    /* The module parameters */
    int pam_config_permit_bypass = 0;
    int pam_config_code_length = 8;

    /* The module configuration */
    config_t pam_config;
    FILE *pam_config_fd;

    /* The module status */
    int pam_status;

    /* The module data */
    const char *pam_user;
    char pam_email[320];
    char *pam_code;
    char *pam_str_buffer;

    /* The module randomization */
    FILE *pam_urandom_fd;
    int pam_random;

    /* Init PAM dialog variables */
    pam_dialog_message[0] = &pam_dialog_message_ptr[0];
    pam_dialog_response = NULL;

    /* Init configuration */
    config_init(&pam_config);

    /* Init configuration file stream */
    if((pam_config_fd = fopen("/etc/aurora/email.conf", "r")) == NULL)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to open configuration";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the configuration */
        config_destroy(&pam_config);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Read and parse the configuration file */
    if(config_read(&pam_config, pam_config_fd) == CONFIG_FALSE)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to read configuration";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Properly destroy the configuration */
        config_destroy(&pam_config);

        /* Properly destroy the configuration file stream */
        fclose(pam_config_fd);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Get settings */
    config_lookup_int(&pam_config, "code_length", 
        &pam_config_code_length);
    config_lookup_int(&pam_config, "permit_bypass", 
        &pam_config_permit_bypass);

    /* Properly destroy the configuration */
    config_destroy(&pam_config);

    /* Get user login */
    if((pam_status = pam_get_user(pam_handle, &pam_user, "login: ")) 
        != PAM_SUCCESS)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = "[ERROR] Unable to get username";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Reject authentication */
        return pam_status;
    }

    /* Initialise the code */
    pam_code = (char*) malloc((pam_config_code_length + 1) * sizeof(char));

    /* Init the random stream */
    if((pam_urandom_fd = fopen("/dev/urandom", "r")) == NULL)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to generate a code";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Reject authentication */
        return PAM_AUTH_ERR;
    }

    /* Extract a random number */
    fread(&pam_random, sizeof(pam_random), 1, pam_urandom_fd);

    /* Properly close the random stream */
    fclose(pam_urandom_fd);

    /* Store the random code */
    snprintf(pam_code, pam_config_code_length + 1, "%u", pam_random);

    /* Look for user email in directory */
    if((pam_status = pam_directory_lookup(pam_handle, pam_user, pam_email)) 
        != PAM_SUCCESS)
    {
        /* Return response (the error has already been transmit) */
        return pam_status;
    }

    /* Transmit the code */
    if((pam_status = pam_transmit_code(pam_handle, (const char*) pam_user,
	(const char*) pam_email, (const char*) pam_code)) != PAM_SUCCESS)
    {
        /* Apply bypass policy */
        if(! pam_config_permit_bypass)
        {
            /* An error occurs */
            pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
            pam_dialog_message_ptr[0].msg = 
                "[ERROR] Unable to send the code";
            pam_converse(pam_handle, 1, pam_dialog_message, 
                &pam_dialog_response);

            /* Free memory */
            free(pam_code);

            /* Reject authentication */
            return pam_status;
        }

        /* Free memory */
        free(pam_code);

        /* Bypass the module */
        return PAM_SUCCESS;
    }

    /* Prompt user code */
    pam_str_buffer = (char*) malloc(
        (672 + 1 + (strlen(pam_user) > 70? strlen(pam_user) - 70: 0)) * 
        sizeof(char));

    sprintf(pam_str_buffer, "\n"\
        "########################################"\
        "########################################\n"\
        "#                                        "\
        "                                      #\n"\
        "#    Hi %-70s #\n"\
        "#    You've just received by email a generated code."\
        "                           #\n"\
        "#    This code is only valid for the current authentication."\
        "                   #\n"\
        "#    To finish your authentication, thank you to enter this code."\
        "              #\n"\
        "#                                        "\
        "                                      #\n"\
        "########################################"\
        "########################################\n\n"\
        "Please type the code: ", pam_user);

    pam_dialog_message_ptr[0].msg_style = PAM_PROMPT_ECHO_ON;
    pam_dialog_message_ptr[0].msg = (const char *) pam_str_buffer;

    if((pam_status = pam_converse(pam_handle, 1, pam_dialog_message, 
        &pam_dialog_response)) != PAM_SUCCESS)
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
            "[ERROR] Unable to converse with PAM";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Free memory */
        free(pam_str_buffer);
        free(pam_code);

        /* Reject authentication */
        return pam_status;
    }

    /* Get user input */
    if(pam_dialog_response)
    {
        if((pam_flags & PAM_DISALLOW_NULL_AUTHTOK) 
            && pam_dialog_response[0].resp == NULL)
        {
            /* An error occurs */
            pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
            pam_dialog_message_ptr[0].msg = 
                "[ERROR] Unable to get the response";
            pam_converse(pam_handle, 1, pam_dialog_message, 
                &pam_dialog_response);

            /* Free memory */
            free(pam_dialog_response);
            free(pam_str_buffer);
            free(pam_code);

            /* Fail authentication */
            return PAM_AUTH_ERR;
        }

        /* Get user input */
        pam_dialog_input = pam_dialog_response[0].resp;
        pam_dialog_response[0].resp = NULL;
    }
    else
    {
        /* An error occurs */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = 
           "[ERROR] Unable to converse with PAM";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Free memory */
        free(pam_str_buffer);
        free(pam_code);

        /* Fail authentication */
        return PAM_CONV_ERR;
    }

    /* Verify user code */
    if(pam_dialog_input == NULL || strcmp(pam_dialog_input, pam_code) != 0)
    {
        /* Announce echec in PAM dialog */
        pam_dialog_message_ptr[0].msg_style = PAM_ERROR_MSG;
        pam_dialog_message_ptr[0].msg = "Wrong code, please try again";
        pam_converse(pam_handle, 1, pam_dialog_message, &pam_dialog_response);

        /* Free memory */
        free(pam_dialog_input);
        free(pam_str_buffer);
        free(pam_code);

        /* Fail authentication */
        return PAM_AUTH_ERR;
    }

    /* Free memory */
    free(pam_dialog_input);
    free(pam_str_buffer);
    free(pam_code);

    /* User successfully logged */
    return PAM_SUCCESS;
}

