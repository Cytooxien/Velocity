package com.velocitypowered.proxy.connection.client;

import static com.velocitypowered.api.network.ProtocolVersion.MINECRAFT_1_8;
import static com.velocitypowered.proxy.connection.VelocityConstants.EMPTY_BYTE_ARRAY;
import static com.velocitypowered.proxy.util.EncryptionUtils.decryptRsa;
import static com.velocitypowered.proxy.util.EncryptionUtils.generateServerId;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent.PreLoginComponentResult;
import com.velocitypowered.api.util.GameProfile;
import com.velocitypowered.proxy.VelocityServer;
import com.velocitypowered.proxy.connection.MinecraftConnection;
import com.velocitypowered.proxy.connection.MinecraftSessionHandler;
import com.velocitypowered.proxy.connection.registry.DimensionData;
import com.velocitypowered.proxy.connection.registry.DimensionInfo;
import com.velocitypowered.proxy.connection.registry.DimensionRegistry;
import com.velocitypowered.proxy.protocol.StateRegistry;
import com.velocitypowered.proxy.protocol.packet.Disconnect;
import com.velocitypowered.proxy.protocol.packet.EncryptionRequest;
import com.velocitypowered.proxy.protocol.packet.EncryptionResponse;
import com.velocitypowered.proxy.protocol.packet.JoinGame;
import com.velocitypowered.proxy.protocol.packet.ServerLogin;
import com.velocitypowered.proxy.protocol.packet.ServerLoginSuccess;
import com.velocitypowered.proxy.protocol.packet.SetCompression;
import io.netty.buffer.ByteBuf;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.nbt.ListBinaryTag;
import net.kyori.adventure.text.Component;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.nullness.qual.MonotonicNonNull;

public class LoginSessionHandler implements MinecraftSessionHandler {

  private static final Logger logger = LogManager.getLogger(LoginSessionHandler.class);

  private final VelocityServer server;
  private final MinecraftConnection mcConnection;
  private final InitialInboundConnection inbound;
  private @MonotonicNonNull ServerLogin login;
  private byte[] verify = EMPTY_BYTE_ARRAY;
  private String serverId;

  LoginSessionHandler(VelocityServer server, MinecraftConnection mcConnection,
            InitialInboundConnection inbound) {
    this.server = Preconditions.checkNotNull(server, "server");
    this.mcConnection = Preconditions.checkNotNull(mcConnection, "mcConnection");
    this.inbound = Preconditions.checkNotNull(inbound, "inbound");
  }

  @Override
  public boolean handle(ServerLogin packet) {
    this.login = packet;
    beginPreLogin();
    return true;
  }

  @Override
  public boolean handle(EncryptionResponse packet) {
    ServerLogin login = this.login;
    if (login == null) {
      throw new IllegalStateException("No ServerLogin packet received yet.");
    }

    if (verify.length == 0) {
      throw new IllegalStateException("No EncryptionRequest packet sent yet.");
    }

    try {
      KeyPair serverKeyPair = server.getServerKeyPair();
      byte[] decryptedVerifyToken = decryptRsa(serverKeyPair, packet.getVerifyToken());
      if (!Arrays.equals(verify, decryptedVerifyToken)) {
        throw new IllegalStateException("Unable to successfully decrypt the verification token.");
      }

      byte[] decryptedSharedSecret = decryptRsa(serverKeyPair, packet.getSharedSecret());
      serverId = generateServerId(decryptedSharedSecret, serverKeyPair.getPublic());

      // Go ahead and enable encryption. Once the client sends EncryptionResponse, encryption
      // is enabled.
      try {
        mcConnection.enableEncryption(decryptedSharedSecret);
      } catch (GeneralSecurityException e) {
        throw new RuntimeException(e);
      }

      //Complete initialization
      completeLoginProtocolPhaseAndInitialize(login.getUsername(),
              GameProfile.forOfflinePlayer(login.getUsername()).getId(), true);
    } catch (GeneralSecurityException e) {
      logger.error("Unable to enable encryption", e);
      mcConnection.close(true);
    }
    return true;
  }

  private void beginPreLogin() {
    ServerLogin login = this.login;
    if (login == null) {
      throw new IllegalStateException("No ServerLogin packet received yet.");
    }
    PreLoginEvent event = new PreLoginEvent(inbound, login.getUsername());
    server.getEventManager().fire(event)
        .thenRunAsync(() -> {
          if (mcConnection.isClosed()) {
            // The player was disconnected
            return;
          }

          PreLoginComponentResult result = event.getResult();
          Optional<Component> disconnectReason = result.getReasonComponent();
          if (disconnectReason.isPresent()) {
            // The component is guaranteed to be provided if the connection was denied.
            mcConnection.closeWith(Disconnect.create(disconnectReason.get(),
                inbound.getProtocolVersion()));
            return;
          }

          if (!result.isForceOfflineMode() && (server.getConfiguration().isOnlineMode() || result
              .isOnlineModeAllowed())) {
            // Request encryption.
            EncryptionRequest request = generateEncryptionRequest();
            this.verify = Arrays.copyOf(request.getVerifyToken(), 4);
            mcConnection.write(request);
          } else {
            completeLoginProtocolPhaseAndInitialize(login.getUsername(),
                    GameProfile.forOfflinePlayer(login.getUsername()).getId(), false);
          }
        }, mcConnection.eventLoop())
        .exceptionally((ex) -> {
          logger.error("Exception in pre-login stage", ex);
          return null;
        });
  }

  private EncryptionRequest generateEncryptionRequest() {
    byte[] verify = new byte[4];
    ThreadLocalRandom.current().nextBytes(verify);

    EncryptionRequest request = new EncryptionRequest();
    request.setPublicKey(server.getServerKeyPair().getPublic().getEncoded());
    request.setVerifyToken(verify);
    return request;
  }

  private void completeLoginProtocolPhaseAndInitialize(
          String username, UUID uuid, boolean onlineMode) {
    int threshold = server.getConfiguration().getCompressionThreshold();
    if (threshold >= 0 && mcConnection.getProtocolVersion().compareTo(MINECRAFT_1_8) >= 0) {
      mcConnection.write(new SetCompression(threshold));
      mcConnection.setCompressionThreshold(threshold);
    }
    ServerLoginSuccess success = new ServerLoginSuccess();
    success.setUsername(username);
    success.setUuid(uuid);
    mcConnection.write(success);

    //Add intermediate verifier
    mcConnection.setState(StateRegistry.PLAY);
    mcConnection.setSessionHandler(
            new LoginVerifySessionHandler(
                    server, mcConnection, inbound,
                    username, uuid, serverId, onlineMode
            )
    );
    //Trigger brand packet
    JoinGame jg = new JoinGame();
    jg.setEntityId(1);
    jg.setGamemode((short) 0);
    jg.setDimension(0);
    jg.setDifficulty((short) 0);
    jg.setIsHardcore(false);
    jg.setMaxPlayers(1);
    jg.setLevelType("default");
    jg.setViewDistance(32);
    jg.setReducedDebugInfo(true);
    DimensionData dimensionData = new DimensionData(
            "minecraft:overworld", 0, true,
            0, false, false, false,
            false, false, false,
            false, false, 256, "minecraft:stone",
            0L, false,
            1d, "minecraft:overworld");
    jg.setDimensionRegistry(new DimensionRegistry(
            ImmutableSet.of(dimensionData),
            ImmutableSet.of("overworld")
    ));
    jg.setDimensionInfo(new DimensionInfo(
            "minecraft:overworld",
            "overworld",
            false,
            false));
    jg.setCurrentDimensionData(dimensionData);
    CompoundBinaryTag.Builder biomeRegistryEntry = CompoundBinaryTag.builder();
    biomeRegistryEntry.putString("type", "minecraft:worldgen/biome");
    CompoundBinaryTag.Builder biomeRegistryValue = CompoundBinaryTag.builder();
    biomeRegistryValue.putString("name", "minecraft:plains");
    biomeRegistryValue.putInt("id", 0);
    biomeRegistryValue.put("entry", CompoundBinaryTag.empty());
    ListBinaryTag.Builder biomeRegistryValueList = ListBinaryTag.builder();
    //biomeRegistryValueList.add(biomeRegistryValue.build());
    biomeRegistryEntry.put("value", biomeRegistryValueList.build());
    jg.setBiomeRegistry(biomeRegistryEntry.build());
    mcConnection.write(jg);
  }

  @Override
  public void handleUnknown(ByteBuf buf) {
    mcConnection.close(true);
  }

  @Override
  public void disconnected() {

  }
}
