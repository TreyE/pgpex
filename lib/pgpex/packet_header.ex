defmodule Pgpex.PacketHeader do
  @packet_types %{
    0 => :reserved,
    1 => :public_key_encrypted_session_key,
    2 => :signature,
    3 => :symmetric_key_encrypted_session,
    4 => :one_pass_signature,
    5 => :secret_key,
    6 => :public_key,
    7 => :secret_subkey,
    8 => :compressed_data,
    9 => :symmetrically_encrypted_data,
    10 => :marker,
    11 => :literal_data,
    12 => :trust,
    13 => :user_id,
    14 => :public_subkey,
    17 => :user_attribute,
    18 => :symmetrically_encrypted_and_integrity_protected_data,
    19 => :modification_detection_code,
    60 => :private_or_experimental,
    61 => :private_or_experimental,
    62 => :private_or_experimental,
    63 => :private_or_experimental
  }

  @type packet_header_types :: unquote(Enum.reduce(Enum.uniq(Map.values(@packet_types)), (
    quote do
     {:invalid, any()}
    end
    ), fn(ele, acc) ->
      quote do
        unquote(acc) | unquote(ele)
      end
    end))

  @type indexes :: pos() | [pos()]
  @type pos :: {non_neg_integer(), non_neg_integer()}

  @type t(val) :: %__MODULE__{
    tag: val,
    packet_length: non_neg_integer(),
    data_length: non_neg_integer(),
    packet_locations: indexes(),
    data_locations: indexes()
  }

  @type t :: t(packet_header_types())

  defstruct [
    tag: nil,
    packet_length: 0,
    data_length: 0,
    packet_locations: nil,
    data_locations: nil
  ]

  @spec new(non_neg_integer(),non_neg_integer(),pos(),non_neg_integer(),pos()) :: t()
  def new(t, pl, p_locs, dl, d_locs) do
    %__MODULE__{
      tag: Map.get(@packet_types, t, {:invalid, t}),
      packet_length: pl,
      packet_locations: p_locs,
      data_length: dl,
      data_locations: d_locs
    }
  end
end
