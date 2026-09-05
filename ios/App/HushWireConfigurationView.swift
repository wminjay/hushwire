import SwiftUI

struct HushWireConfigurationView: View {
  private enum FocusedField: Hashable {
    case profileName
    case dnsServers
    case trustedWiFiSSIDs
  }

  @ObservedObject var controller: HushWireIOSController
  let importAction: () -> Void

  @State private var showingProfileSelector = false
  @State private var showingAllRoutes = false
  @State private var showingAllExceptions = false
  @State private var showingDeleteConfirmation = false
  @State private var showingAutoConnectConfirmation = false
  @State private var draftName = ""
  @State private var draftPolicy = HushWireRoutePolicy.hostRoutesOnly
  @State private var draftDNSServers = ""
  @State private var draftTrustedWiFiSSIDs = ""
  @State private var draftAutoConnectOutsideTrustedWiFi = false
  @FocusState private var focusedField: FocusedField?

  var body: some View {
    NavigationStack {
      ScrollView {
        if let profile = controller.selectedProfile,
          let inspection = controller.profileInspection
        {
          configuredContent(profile: profile, inspection: inspection)
            .padding(.horizontal, HushWireTheme.pagePadding)
            .padding(.top, 12)
            .padding(.bottom, 112)
        } else {
          emptyContent
            .padding(.horizontal, HushWireTheme.pagePadding)
            .padding(.top, 12)
            .padding(.bottom, 112)
        }
      }
      .scrollDismissesKeyboard(.immediately)
      .scrollIndicators(.hidden)
      .background(HushWireTheme.canvas)
      .navigationTitle("配置")
      .toolbar {
        ToolbarItem(placement: .topBarTrailing) {
          Button(action: importAction) {
            Label("导入 TOML", systemImage: "square.and.arrow.down")
          }
          .disabled(!controller.canEditProfiles)
        }
        ToolbarItemGroup(placement: .keyboard) {
          Spacer()
          Button("完成") {
            focusedField = nil
          }
          .accessibilityIdentifier("hushwire.keyboard.done")
        }
      }
    }
    .sheet(isPresented: $showingProfileSelector) {
      HushWireProfileSelectorSheet(controller: controller, importAction: importAction)
    }
    .confirmationDialog(
      "删除“\(controller.selectedProfile?.name ?? "")”？",
      isPresented: $showingDeleteConfirmation,
      titleVisibility: .visible
    ) {
      if let profile = controller.selectedProfile {
        Button("从本机删除配置", role: .destructive) {
          controller.deleteProfile(profile)
        }
      }
      Button("取消", role: .cancel) {}
    } message: {
      Text("对应的 TOML、私钥与 PSK 会从 HushWire 的本机 Keychain 项中删除。")
    }
    .confirmationDialog(
      "启用自动全局连接？",
      isPresented: $showingAutoConnectConfirmation,
      titleVisibility: .visible
    ) {
      Button("启用并保存") {
        saveDraft()
      }
      Button("取消", role: .cancel) {}
    } message: {
      Text("离开可信 Wi-Fi 后，iOS 会按需启动 HushWire，并把默认 IPv4 流量与所选 DNS 交给隧道。")
    }
    .onAppear(perform: synchronizeDraft)
    .onChange(of: controller.selectedProfileID) { _, _ in
      synchronizeDraft()
    }
    .onChange(of: draftPolicy) { _, newValue in
      if newValue == .hostRoutesOnly {
        draftDNSServers = ""
      }
    }
  }

  private func configuredContent(
    profile: HushWireProfile,
    inspection: HushWireProfileInspection
  ) -> some View {
    VStack(spacing: HushWireTheme.sectionSpacing) {
      HushWireProfileButton(
        profile: profile,
        enabled: controller.canEditProfiles,
        action: { showingProfileSelector = true }
      )

      if !controller.canEditProfiles {
        HushWireCallout(
          symbol: "lock.fill",
          title: "连接期间为只读",
          detail: "断开隧道后即可切换配置，或修改路由、DNS 与自动连接策略。",
          tint: HushWireTheme.warning
        )
      }

      routingPolicySection
      automationSection
      saveChangesButton

      VStack(spacing: 9) {
        HushWireSectionLabel(title: "接口与路由详情")
        interfaceCard(inspection.summary)
      }

      VStack(spacing: 9) {
        HushWireSectionLabel(title: "恢复与保活")
        recoveryCard(inspection)
      }

      HushWireCallout(
        symbol: "lock.shield.fill",
        title: "凭据已保护",
        detail: "私钥与预共享密钥保存在本机 Keychain，不会在界面、VPN 偏好或诊断报告中显示。",
        tint: HushWireTheme.healthy
      )

      Button {
        controller.validateSelectedProfile()
      } label: {
        Label("验证配置", systemImage: "checkmark.shield")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 48)
      }
      .buttonStyle(.bordered)
      .buttonBorderShape(.capsule)
      .disabled(controller.isBusy)

      Button("删除这份配置", role: .destructive) {
        showingDeleteConfirmation = true
      }
      .disabled(!controller.canEditProfiles)

      Text(controller.activity)
        .font(.footnote)
        .foregroundStyle(controller.lastError == nil ? Color.secondary : Color.red)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 4)
    }
  }

  private var routingPolicySection: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "路由与 DNS")
      HushWireCard {
        VStack(alignment: .leading, spacing: 16) {
          VStack(alignment: .leading, spacing: 7) {
            Text("配置名称")
              .font(.caption.weight(.semibold))
              .foregroundStyle(.secondary)
            TextField("配置名称", text: $draftName)
              .textInputAutocapitalization(.never)
              .focused($focusedField, equals: .profileName)
              .padding(.horizontal, 12)
              .frame(minHeight: 44)
              .background(HushWireTheme.surface)
              .clipShape(RoundedRectangle(cornerRadius: 11, style: .continuous))
          }

          VStack(alignment: .leading, spacing: 8) {
            Text("流量范围")
              .font(.caption.weight(.semibold))
              .foregroundStyle(.secondary)
            Picker("网络策略", selection: $draftPolicy) {
              Text("指定地址").tag(HushWireRoutePolicy.hostRoutesOnly)
              Text("自定义分流").tag(HushWireRoutePolicy.splitRoutes)
              Text("全局").tag(HushWireRoutePolicy.fullTunnel)
            }
            .pickerStyle(.segmented)
          }

          Text(draftPolicy.detail)
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

          if draftPolicy.allowsDNS {
            VStack(alignment: .leading, spacing: 6) {
              Text("DNS 服务器")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
              TextField("例如 1.1.1.1, 8.8.8.8", text: $draftDNSServers)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.numbersAndPunctuation)
                .textFieldStyle(.roundedBorder)
                .focused($focusedField, equals: .dnsServers)
              Text("DNS 地址必须由 allowed_ips 实际送入隧道，否则验证会拒绝保存。")
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
          }

        }
        .padding(16)
      }
      .disabled(!controller.canEditProfiles)
    }
  }

  private var automationSection: some View {
    VStack(spacing: 9) {
      HushWireSectionLabel(title: "自动连接")
      HushWireCard {
        VStack(alignment: .leading, spacing: 15) {
          VStack(alignment: .leading, spacing: 7) {
            Text("可信 Wi-Fi")
              .font(.caption.weight(.semibold))
              .foregroundStyle(.secondary)
            TextField(
              "每行一个，例如 Home Wi-Fi",
              text: $draftTrustedWiFiSSIDs,
              axis: .vertical
            )
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .lineLimit(1...3)
            .textFieldStyle(.roundedBorder)
            .focused($focusedField, equals: .trustedWiFiSSIDs)
            .accessibilityIdentifier("hushwire.trusted-wifi.ssids")
            Text("连接这些 Wi-Fi 时自动断开；名称按大小写精确匹配。")
              .font(.caption2)
              .foregroundStyle(.tertiary)
          }

          Divider()

          Toggle(isOn: $draftAutoConnectOutsideTrustedWiFi) {
            VStack(alignment: .leading, spacing: 3) {
              Text("离开可信 Wi-Fi 后自动连接")
                .font(.subheadline.weight(.semibold))
              Text("适用于其他 Wi-Fi 与蜂窝网络")
                .font(.caption)
                .foregroundStyle(.secondary)
            }
          }
          .accessibilityIdentifier("hushwire.auto-connect")

          Text(
            draftAutoConnectOutsideTrustedWiFi
              ? "网络产生流量时，iOS 会按需启动 HushWire；App 无需保持打开。"
              : "关闭时，离开可信 Wi-Fi 不会主动启动隧道。"
          )
          .font(.caption2)
          .foregroundStyle(.tertiary)
          .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
      }
      .disabled(!controller.canEditProfiles)
    }
  }

  private var saveChangesButton: some View {
    Button {
      if draftPolicy == .fullTunnel,
        draftAutoConnectOutsideTrustedWiFi,
        controller.selectedProfile?.autoConnectOutsideTrustedWiFi != true
      {
        showingAutoConnectConfirmation = true
      } else {
        saveDraft()
      }
    } label: {
      Label(
        hasUnsavedChanges ? "保存更改" : "配置已保存",
        systemImage: hasUnsavedChanges ? "checkmark" : "checkmark.circle.fill"
      )
      .font(.headline)
      .frame(maxWidth: .infinity, minHeight: 50)
    }
    .buttonStyle(.borderedProminent)
    .buttonBorderShape(.capsule)
    .accessibilityIdentifier("hushwire.policy.save")
    .disabled(
      !controller.canEditProfiles
        || !hasUnsavedChanges
        || draftName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
  }

  private func interfaceCard(_ summary: HushWireConfigurationSummary) -> some View {
    HushWireCard {
      HushWireValueRow(title: "接口地址", value: summary.interface, monospaced: true)
      HushWireDivider()
      HushWireValueRow(title: "Endpoint", value: summary.endpointDescription, monospaced: true)
      HushWireDivider()
      HushWireValueRow(title: "传输", value: summary.transport, monospaced: true)
      HushWireDivider()
      HushWireValueRow(title: "MTU", value: String(summary.mtu), monospaced: true)
      HushWireDivider()
      HushWireValueRow(title: "Peer", value: String(summary.peerCount), monospaced: true)
      HushWireDivider()
      DisclosureGroup(isExpanded: $showingAllRoutes) {
        VStack(alignment: .leading, spacing: 8) {
          ForEach(Array(summary.routes.enumerated()), id: \.offset) { _, route in
            Text(route)
              .font(.footnote.monospaced())
              .textSelection(.enabled)
          }
        }
        .padding(.top, 10)
      } label: {
        HStack {
          Text("允许路由")
          Spacer()
          Text("\(summary.routes.count) 条")
            .foregroundStyle(.secondary)
        }
      }
      .padding(.horizontal, 16)
      .padding(.vertical, 14)
      HushWireDivider()
      DisclosureGroup(isExpanded: $showingAllExceptions) {
        VStack(alignment: .leading, spacing: 8) {
          if summary.directRoutes.isEmpty {
            Text("无")
              .font(.footnote)
              .foregroundStyle(.secondary)
          } else {
            ForEach(Array(summary.directRoutes.enumerated()), id: \.offset) { _, route in
              Text(route)
                .font(.footnote.monospaced())
                .textSelection(.enabled)
            }
          }
        }
        .padding(.top, 10)
      } label: {
        HStack {
          Text("直连例外")
          Spacer()
          Text(summary.directRoutes.isEmpty ? "无" : "\(summary.directRoutes.count) 条")
            .foregroundStyle(.secondary)
        }
      }
      .padding(.horizontal, 16)
      .padding(.vertical, 14)
      HushWireDivider()
      HushWireValueRow(title: "DNS", value: summary.dnsDescription, monospaced: true)
    }
  }

  private func recoveryCard(_ inspection: HushWireProfileInspection) -> some View {
    HushWireCard {
      ForEach(Array(inspection.peers.enumerated()), id: \.element.id) { index, peer in
        if index > 0 { HushWireDivider() }
        VStack(alignment: .leading, spacing: 0) {
          if inspection.peers.count > 1 {
            Text(peer.name)
              .font(.caption.weight(.semibold))
              .foregroundStyle(.secondary)
              .padding(.horizontal, 16)
              .padding(.top, 14)
          }
          HushWireValueRow(
            title: "Keepalive",
            value: peer.persistentKeepalive == 0 ? "关闭" : "\(peer.persistentKeepalive)s",
            monospaced: true
          )
          if inspection.summary.transport == "UDP" {
            HushWireDivider()
            HushWireValueRow(
              title: "UDP Rebind",
              value: peer.udpRebindAfter == 0 ? "关闭" : "\(peer.udpRebindAfter)s",
              monospaced: true
            )
          } else {
            HushWireDivider()
            HushWireValueRow(
              title: "TCP Session Timeout",
              value: peer.sessionTimeout == 0 ? "关闭" : "\(peer.sessionTimeout)s",
              monospaced: true
            )
          }
          HushWireDivider()
          HushWireValueRow(
            title: "已解析",
            value: peer.resolvedEndpoint,
            monospaced: true
          )
        }
      }
    }
  }

  private var emptyContent: some View {
    VStack(spacing: 22) {
      Spacer(minLength: 24)
      Image(systemName: "doc.badge.plus")
        .font(.system(size: 44))
        .foregroundStyle(HushWireTheme.primary)
        .frame(width: 96, height: 96)
        .background(HushWireTheme.primary.opacity(0.08), in: Circle())
      Text("还没有配置")
        .font(.title.bold())
      Text("导入 TOML 后，会先检查地址、Peer、路由、DNS 和恢复参数。")
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
      Button(action: importAction) {
        Label("导入 TOML", systemImage: "square.and.arrow.down")
          .font(.headline)
          .frame(maxWidth: .infinity, minHeight: 50)
      }
      .buttonStyle(.borderedProminent)
      .buttonBorderShape(.capsule)
    }
  }

  private var hasUnsavedChanges: Bool {
    guard let profile = controller.selectedProfile else { return false }
    return draftName != profile.name
      || draftPolicy != profile.routePolicy
      || draftDNSServers != profile.dnsServers.joined(separator: ", ")
      || draftTrustedWiFiSSIDs != profile.trustedWiFiSSIDs.joined(separator: "\n")
      || draftAutoConnectOutsideTrustedWiFi != profile.autoConnectOutsideTrustedWiFi
  }

  private func synchronizeDraft() {
    guard let profile = controller.selectedProfile else {
      draftName = ""
      draftPolicy = .hostRoutesOnly
      draftDNSServers = ""
      draftTrustedWiFiSSIDs = ""
      draftAutoConnectOutsideTrustedWiFi = false
      return
    }
    draftName = profile.name
    draftPolicy = profile.routePolicy
    draftDNSServers = profile.dnsServers.joined(separator: ", ")
    draftTrustedWiFiSSIDs = profile.trustedWiFiSSIDs.joined(separator: "\n")
    draftAutoConnectOutsideTrustedWiFi = profile.autoConnectOutsideTrustedWiFi
  }

  private func saveDraft() {
    controller.updateSelectedProfile(
      name: draftName,
      routePolicy: draftPolicy,
      dnsServersText: draftDNSServers,
      trustedWiFiSSIDsText: draftTrustedWiFiSSIDs,
      autoConnectOutsideTrustedWiFi: draftAutoConnectOutsideTrustedWiFi
    )
  }
}
