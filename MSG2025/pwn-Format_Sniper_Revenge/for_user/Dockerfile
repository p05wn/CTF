FROM alpine:latest

ENV user format_sniper
ENV port 5315

# Install packages
RUN apk add --no-cache socat

# Change tmp permissions
RUN chmod 1733 /tmp /var/tmp /dev/shm

# Add user
RUN adduser --disabled-password --gecos "" $user
RUN chown -R root:root /home/$user

# Add files
COPY --chown=root:$user \
    format-sniper_revenge launcher libc.so.6 ld-linux-x86-64.so.2 flag \
    /home/$user/

# chown & chmod files
RUN chmod 2755 /home/$user/format-sniper_revenge /home/$user/launcher \
 && chmod 755 /home/$user/libc.so.6 /home/$user/libc.so.6 \
 && chmod 440 /home/$user/flag
#
# Run server
WORKDIR /home/$user
CMD socat TCP-LISTEN:$port,reuseaddr,fork EXEC:/home/$user/launcher,stderr
USER $user
EXPOSE $port
