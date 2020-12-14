package com.velocitypowered.proxy.connection.client;

import static com.google.common.net.UrlEscapers.urlFormParameterEscaper;
import static com.velocitypowered.proxy.VelocityServer.GENERAL_GSON;

import com.google.common.base.Preconditions;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent.LoginStatus;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.permission.PermissionsSetupEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.util.GameProfile;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.MinecraftSessionHandler;
import com.velocitypowered.proxy.protocol.StateRegistry;
import com.velocitypowered.proxy.protocol.packet.PluginMessage;
import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.asynchttpclient.ListenableFuture;
import org.asynchttpclient.Response;

public class LoginVerifySessionHandler implements MinecraftSessionHandler {
  private static final Logger logger = LogManager.getLogger(LoginVerifySessionHandler.class);

  private static final String MOJANG_HASJOINED_URL =
      "https://sessionserver.mojang.com/session/minecraft/hasJoined?username=%s&serverId=%s";

  private final VelocityServer server;
  private final MinecraftConnection mcConnection;
  private final InitialInboundConnection inbound;
  private final String username;
  private final UUID uuid;
  private final String serverId;
  private final boolean onlineMode;

  private boolean fired = false;

  private ConnectedPlayer connectedPlayer;

  LoginVerifySessionHandler(VelocityServer server, MinecraftConnection mcConnection,
                            InitialInboundConnection inbound, String username,
                            UUID uuid, String serverId,
                            boolean onlineMode) {
    this.server = Preconditions.checkNotNull(server, "server");
    this.mcConnection = Preconditions.checkNotNull(mcConnection, "mcConnection");
    this.inbound = Preconditions.checkNotNull(inbound, "inbound");
    this.username = Preconditions.checkNotNull(username, "username");
    this.uuid = Preconditions.checkNotNull(uuid, "uuid");
    if (onlineMode) {
      this.serverId = Preconditions.checkNotNull(serverId, "serverId");
    } else {
      this.serverId = serverId;
    }
    this.onlineMode = onlineMode;
  }

  @Override
  public boolean handle(PluginMessage packet) {
    if (fired) {
      return false;
    }
    if (packet.getChannel().equals("minecraft:brand") || packet.getChannel().equals("MC|Brand")) {
      fired = true;
      if (onlineMode) {
        //Verify player credentials
        String playerIp = ((InetSocketAddress) mcConnection.getRemoteAddress()).getHostString();
        String url = String.format(MOJANG_HASJOINED_URL,
            urlFormParameterEscaper().escape(username), serverId);

        if (server.getConfiguration().shouldPreventClientProxyConnections()) {
          url += "&ip=" + urlFormParameterEscaper().escape(playerIp);
        }

        ListenableFuture<Response> hasJoinedResponse = server.getAsyncHttpClient().prepareGet(url)
            .execute();
        hasJoinedResponse.addListener(() -> {
          if (mcConnection.isClosed()) {
            // The player disconnected after we authenticated them.
            return;
          }

          try {
            Response profileResponse = hasJoinedResponse.get();
            if (profileResponse.getStatusCode() == 200) {
              // All went well, initialize the session.
              initializePlayer(GENERAL_GSON.fromJson(profileResponse.getResponseBody(),
                  GameProfile.class), true);
            } else if (profileResponse.getStatusCode() == 204) {
              // Apparently an offline-mode user logged onto this online-mode proxy.
              inbound.disconnect(server.getConfiguration().getMessages().getOnlineModeOnly());
            } else {
              // Something else went wrong
              logger.error(
                  "Got an unexpected error code {} whilst contacting Mojang to log in {} ({})",
                  profileResponse.getStatusCode(), username, playerIp);
              mcConnection.close(true);
            }
          } catch (ExecutionException e) {
            logger.error("Unable to authenticate with Mojang", e);
            mcConnection.close(true);
            return;
          } catch (InterruptedException e) {
            // not much we can do usefully
            Thread.currentThread().interrupt();
            return;
          }
        }, mcConnection.eventLoop());
      } else {
        initializePlayer(GameProfile.forOfflinePlayer(username), false);
      }
    }
    return true;
  }

  @Override
  public void disconnected() {
    // the user cancelled the login process
    if (connectedPlayer != null) {
      connectedPlayer.teardown();
    }
  }

  private void initializePlayer(GameProfile profile, boolean onlineMode) {
    // Some connection types may need to alter the game profile.
    profile = mcConnection.getType().addGameProfileTokensIfRequired(profile,
        server.getConfiguration().getPlayerInfoForwardingMode());
    GameProfileRequestEvent profileRequestEvent = new GameProfileRequestEvent(inbound, profile,
        onlineMode);
    final GameProfile finalProfile = profile;

    server.getEventManager().fire(profileRequestEvent).thenComposeAsync(profileEvent -> {
      if (mcConnection.isClosed()) {
        // The player disconnected after we authenticated them.
        return CompletableFuture.completedFuture(null);
      }

      // Initiate a regular connection and move over to it.
      ConnectedPlayer player = new ConnectedPlayer(server, profileEvent.getGameProfile(),
          mcConnection, inbound.getVirtualHost().orElse(null), onlineMode);
      this.connectedPlayer = player;
      if (!server.canRegisterConnection(player)) {
        player.disconnect0(server.getConfiguration().getMessages().getAlreadyConnected(), true);
        return CompletableFuture.completedFuture(null);
      }

      logger.info("{} has connected", player);

      return server.getEventManager()
          .fire(new PermissionsSetupEvent(player, ConnectedPlayer.DEFAULT_PERMISSIONS))
          .thenAcceptAsync(event -> {
            if (!mcConnection.isClosed()) {
              // wait for permissions to load, then set the players permission function
              player.setPermissionFunction(event.createFunction(player));

              mcConnection.setAssociation(player);

              server.getEventManager().fire(new LoginEvent(player))
                  .thenAcceptAsync(event2 -> {
                    if (mcConnection.isClosed()) {
                      // The player was disconnected
                      server.getEventManager().fireAndForget(new DisconnectEvent(player,
                          LoginStatus.CANCELLED_BY_USER_BEFORE_COMPLETE));
                      return;
                    }

                    Optional<Component> reason = event2.getResult().getReasonComponent();
                    if (reason.isPresent()) {
                      player.disconnect0(reason.get(), true);
                    } else {
                      if (!server.registerConnection(player)) {
                        player.disconnect0(server.getConfiguration().getMessages()
                            .getAlreadyConnected(), true);
                        return;
                      }

                      mcConnection.setSessionHandler(new InitialConnectSessionHandler(player));
                      server.getEventManager().fire(new PostLoginEvent(player))
                          .thenRun(() -> connectToInitialServer(player));
                    }
                  }, mcConnection.eventLoop())
                  .exceptionally((ex) -> {
                    logger.error("Exception while completing login "
                            + "initialisation phase for {}", player, ex);
                    return null;
                  });
            }
          }, mcConnection.eventLoop());
    }, mcConnection.eventLoop()).exceptionally((ex) -> {
      logger.error("Exception during connection of {}", finalProfile, ex);
      return null;
    });
  }

  private void connectToInitialServer(ConnectedPlayer player) {
    Optional<RegisteredServer> initialFromConfig = player.getNextServerToTry();
    PlayerChooseInitialServerEvent event = new PlayerChooseInitialServerEvent(player,
        initialFromConfig.orElse(null));

    server.getEventManager().fire(event)
        .thenRunAsync(() -> {
          Optional<RegisteredServer> toTry = event.getInitialServer();
          if (!toTry.isPresent()) {
            player.disconnect0(server.getConfiguration().getMessages()
                .getNoAvailableServers(), true);
            return;
          }
          player.createConnectionRequest(toTry.get()).fireAndForget();
        }, mcConnection.eventLoop())
        .exceptionally((ex) -> {
          logger.error("Exception while connecting {} to initial server", player, ex);
          return null;
        });
  }
}
